#include "oidcAuthCodeProvider.hpp"

#include <atomic>
#include <random>
#include <sstream>
#include <stdexcept>
#include <thread>

#include "nlohmann/json.hpp"

#include "../../util/browserInteraction.hpp"
#include "../../util/b64decoder.hpp"
#include "../../util/cryptUtils.hpp"
#include "../../util/writeLog.hpp"

#include "tokenCacheAuthProviderBase.hpp"
#include "tokens/tokenCache.hpp"

// windowsLean.hpp now includes winsock2.h and ws2tcpip.h
// before windows.h, so we don't need to include them again.
// wincrypt.h is needed for SHA-256 (PKCE) and base64 encoding.
#include "../../util/windowsLean.hpp"
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

using json = nlohmann::json;


// ============================================================================
// PKCE Utilities
// ============================================================================

namespace {

std::string generateCodeVerifier() {
  // RFC 7636: code_verifier is a high-entropy cryptographic random string
  // using unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
  // with a minimum length of 43 and a maximum length of 128 characters.
  static const char charset[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  static const int charsetSize    = sizeof(charset) - 1;
  static const int verifierLength = 64;

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dist(0, charsetSize - 1);

  std::string verifier;
  verifier.reserve(verifierLength);
  for (int i = 0; i < verifierLength; ++i) {
    verifier += charset[dist(gen)];
  }
  return verifier;
}

std::string sha256Digest(const std::string& input) {
  // Use Windows CryptoAPI for SHA-256 hashing.
  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;
  BYTE hash[32]    = {0};
  DWORD hashLen    = 32;

  if (!CryptAcquireContext(
          &hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
    throw std::runtime_error("CryptAcquireContext failed for SHA-256");
  }

  if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
    CryptReleaseContext(hProv, 0);
    throw std::runtime_error("CryptCreateHash failed for SHA-256");
  }

  if (!CryptHashData(hHash,
                     reinterpret_cast<const BYTE*>(input.c_str()),
                     static_cast<DWORD>(input.length()),
                     0)) {
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    throw std::runtime_error("CryptHashData failed for SHA-256");
  }

  if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    throw std::runtime_error("CryptGetHashParam failed for SHA-256");
  }

  CryptDestroyHash(hHash);
  CryptReleaseContext(hProv, 0);

  return std::string(reinterpret_cast<char*>(hash), hashLen);
}

std::string base64UrlEncode(const std::string& input) {
  // Standard base64 encode using Windows CryptoAPI, then convert to
  // base64url per RFC 4648 Section 5.
  DWORD requiredSize = 0;
  CryptBinaryToStringA(reinterpret_cast<const BYTE*>(input.data()),
                       static_cast<DWORD>(input.size()),
                       CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                       nullptr,
                       &requiredSize);

  std::string encoded(requiredSize, '\0');
  CryptBinaryToStringA(reinterpret_cast<const BYTE*>(input.data()),
                       static_cast<DWORD>(input.size()),
                       CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                       encoded.data(),
                       &requiredSize);

  // Trim any trailing null terminators that Windows may add.
  while (!encoded.empty() && encoded.back() == '\0') {
    encoded.pop_back();
  }

  // Convert base64 to base64url: replace + with -, / with _, remove = padding.
  for (char& c : encoded) {
    if (c == '+') {
      c = '-';
    } else if (c == '/') {
      c = '_';
    }
  }
  while (!encoded.empty() && encoded.back() == '=') {
    encoded.pop_back();
  }

  return encoded;
}

std::string generateCodeChallenge(const std::string& codeVerifier) {
  // RFC 7636 Section 4.2: code_challenge = BASE64URL(SHA256(code_verifier))
  std::string hash = sha256Digest(codeVerifier);
  return base64UrlEncode(hash);
}

std::string generateState() {
  // Generate a random state parameter for CSRF protection.
  // Reuse the verifier generator but use a shorter length.
  return generateCodeVerifier().substr(0, 32);
}

std::string urlEncodeOidc(CURL* curl, const std::string& s) {
  // Wrap curl_easy_escape so we can make sure any memory
  // allocated is immediately freed.
  char* encoded =
      curl_easy_escape(curl, s.c_str(), static_cast<int>(s.length()));
  std::string result(encoded);
  curl_free(encoded);
  return result;
}


// ============================================================================
// Local HTTP Callback Server
// ============================================================================

struct CallbackResult {
    std::string authorizationCode;
    std::string state;
    std::string error;
    std::string errorDescription;
    std::atomic<bool> received{false};
};

std::string parseQueryParam(const std::string& query, const std::string& key) {
  std::string search = key + "=";
  auto pos           = query.find(search);
  if (pos == std::string::npos) {
    return "";
  }
  pos += search.length();
  auto end = query.find('&', pos);
  std::string value =
      (end == std::string::npos) ? query.substr(pos)
                                 : query.substr(pos, end - pos);

  // Basic URL decode for the value (handle %XX sequences).
  std::string decoded;
  for (size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '%' && i + 2 < value.size()) {
      int hex = 0;
      std::istringstream iss(value.substr(i + 1, 2));
      iss >> std::hex >> hex;
      decoded += static_cast<char>(hex);
      i += 2;
    } else if (value[i] == '+') {
      decoded += ' ';
    } else {
      decoded += value[i];
    }
  }
  return decoded;
}

bool startCallbackServer(unsigned short port,
                         CallbackResult& result,
                         int timeoutSeconds) {
  WriteLog(LL_DEBUG,
           "  Starting local callback server on port " +
               std::to_string(port));

  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    WriteLog(LL_ERROR, "  ERROR: WSAStartup failed");
    return false;
  }

  SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (serverSocket == INVALID_SOCKET) {
    WriteLog(LL_ERROR, "  ERROR: Failed to create socket");
    WSACleanup();
    return false;
  }

  // Allow port reuse so rapid reconnections don't fail.
  int opt = 1;
  setsockopt(serverSocket,
             SOL_SOCKET,
             SO_REUSEADDR,
             reinterpret_cast<const char*>(&opt),
             sizeof(opt));

  sockaddr_in serverAddr     = {};
  serverAddr.sin_family      = AF_INET;
  serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  serverAddr.sin_port        = htons(port);

  if (bind(serverSocket,
           reinterpret_cast<sockaddr*>(&serverAddr),
           sizeof(serverAddr)) == SOCKET_ERROR) {
    WriteLog(LL_ERROR,
             "  ERROR: Failed to bind to port " + std::to_string(port) +
                 ". Is another process using it?");
    closesocket(serverSocket);
    WSACleanup();
    return false;
  }

  if (listen(serverSocket, 1) == SOCKET_ERROR) {
    WriteLog(LL_ERROR, "  ERROR: Failed to listen on socket");
    closesocket(serverSocket);
    WSACleanup();
    return false;
  }

  // Use select() with a timeout so we don't block forever waiting
  // for the user to complete authentication in the browser.
  fd_set readSet;
  FD_ZERO(&readSet);
  FD_SET(serverSocket, &readSet);
  timeval timeout  = {};
  timeout.tv_sec   = timeoutSeconds;
  timeout.tv_usec  = 0;

  int selectResult = select(0, &readSet, nullptr, nullptr, &timeout);
  if (selectResult <= 0) {
    WriteLog(LL_ERROR,
             "  ERROR: Timeout waiting for authorization callback (" +
                 std::to_string(timeoutSeconds) + "s)");
    closesocket(serverSocket);
    WSACleanup();
    return false;
  }

  SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
  if (clientSocket == INVALID_SOCKET) {
    WriteLog(LL_ERROR, "  ERROR: Failed to accept connection");
    closesocket(serverSocket);
    WSACleanup();
    return false;
  }

  // Read the HTTP request from the browser redirect.
  char buffer[4096] = {0};
  int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

  if (bytesReceived > 0) {
    std::string request(buffer, bytesReceived);
    WriteLog(LL_TRACE, "  Callback received HTTP request");

    // Parse the GET request line:
    // "GET /callback?code=xxx&state=yyy HTTP/1.1"
    auto lineEnd = request.find("\r\n");
    std::string requestLine =
        (lineEnd != std::string::npos) ? request.substr(0, lineEnd) : request;

    auto queryStart = requestLine.find('?');
    auto httpStart  = requestLine.find(" HTTP/");
    if (queryStart != std::string::npos && httpStart != std::string::npos) {
      std::string queryString =
          requestLine.substr(queryStart + 1, httpStart - queryStart - 1);

      result.authorizationCode =
          parseQueryParam(queryString, "code");
      result.state =
          parseQueryParam(queryString, "state");
      result.error =
          parseQueryParam(queryString, "error");
      result.errorDescription =
          parseQueryParam(queryString, "error_description");
    }

    // Send a user-friendly response back to the browser.
    std::string responseBody;
    if (!result.error.empty()) {
      responseBody =
          "<html><body>"
          "<h2>Authentication Failed</h2>"
          "<p>Error: " + result.error + "</p>"
          "<p>" + result.errorDescription + "</p>"
          "<p>You can close this window and try again.</p>"
          "</body></html>";
    } else {
      responseBody =
          "<html><body>"
          "<h2>Authentication Successful</h2>"
          "<p>You have been authenticated successfully.</p>"
          "<p>You can close this browser window now.</p>"
          "<script>setTimeout(function(){window.close();},3000);</script>"
          "</body></html>";
    }

    std::string httpResponse =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: " + std::to_string(responseBody.size()) + "\r\n"
        "Connection: close\r\n"
        "\r\n" +
        responseBody;

    send(clientSocket,
         httpResponse.c_str(),
         static_cast<int>(httpResponse.size()),
         0);

    result.received = true;
  }

  // Cleanup
  closesocket(clientSocket);
  closesocket(serverSocket);
  WSACleanup();

  return result.received;
}


// ============================================================================
// OIDC Discovery
// ============================================================================

struct OidcEndpoints {
    std::string authorizationEndpoint;
    std::string tokenEndpoint;
};

OidcEndpoints discoverOidcEndpoints(
    CURL* curl,
    const std::string& discoveryUrl,
    std::string* responseData,
    std::map<std::string, std::string>* responseHeaderData) {

  OidcEndpoints endpoints;

  responseData->clear();
  responseHeaderData->clear();
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, nullptr);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, nullptr);
  curl_easy_setopt(curl, CURLOPT_URL, discoveryUrl.c_str());

  CURLcode res = curl_easy_perform(curl);
  WriteLog(LL_DEBUG,
           "  OIDC discovery CURLcode response: " + std::to_string(res));
  WriteLog(LL_TRACE,
           "  OIDC discovery response: " + *responseData);

  if (res != CURLE_OK) {
    WriteLog(LL_ERROR,
             "  ERROR: OIDC discovery request failed with CURLcode: " +
                 std::to_string(res));
    return endpoints;
  }

  json discoveryData;
  try {
    discoveryData = json::parse(*responseData);
  } catch (const json::parse_error& e) {
    WriteLog(LL_ERROR,
             "  ERROR: Failed to parse OIDC discovery response as JSON: " +
                 std::string(e.what()) +
                 " | Raw response: " + *responseData);
    return endpoints;
  }

  if (discoveryData.contains("error")) {
    std::string errorMsg = discoveryData["error"].is_string()
                               ? discoveryData["error"].get<std::string>()
                               : discoveryData["error"].dump();
    WriteLog(LL_ERROR,
             "  ERROR: OIDC discovery endpoint returned error: " + errorMsg +
                 " | URL was: " + discoveryUrl);
    return endpoints;
  }

  if (discoveryData.contains("authorization_endpoint")) {
    endpoints.authorizationEndpoint =
        discoveryData["authorization_endpoint"].get<std::string>();
  } else {
    WriteLog(LL_ERROR,
             "  ERROR: OIDC discovery response missing "
             "'authorization_endpoint'. Verify the discovery URL includes "
             "the full path (e.g., "
             "https://host/realms/REALM/.well-known/openid-configuration). "
             "URL was: " + discoveryUrl);
  }

  if (discoveryData.contains("token_endpoint")) {
    endpoints.tokenEndpoint =
        discoveryData["token_endpoint"].get<std::string>();
  } else {
    WriteLog(LL_ERROR,
             "  ERROR: OIDC discovery response missing 'token_endpoint'. "
             "URL was: " + discoveryUrl);
  }

  WriteLog(LL_DEBUG,
           "  Discovered authorization_endpoint: " +
               endpoints.authorizationEndpoint);
  WriteLog(LL_DEBUG,
           "  Discovered token_endpoint: " + endpoints.tokenEndpoint);

  return endpoints;
}


// ============================================================================
// Token Exchange
// ============================================================================

struct TokenResponse {
    std::string accessToken;
    std::string refreshToken;
    bool success = false;
};

TokenResponse exchangeAuthCodeForTokens(
    CURL* curl,
    const std::string& tokenEndpoint,
    const std::string& authorizationCode,
    const std::string& codeVerifier,
    const std::string& redirectUri,
    const std::string& clientId,
    const std::string& clientSecret,
    std::string* responseData,
    std::map<std::string, std::string>* responseHeaderData) {

  TokenResponse tokenResponse;

  std::ostringstream postBody;
  postBody << "grant_type=" << urlEncodeOidc(curl, "authorization_code");
  postBody << "&code=" << urlEncodeOidc(curl, authorizationCode);
  postBody << "&redirect_uri=" << urlEncodeOidc(curl, redirectUri);
  postBody << "&client_id=" << urlEncodeOidc(curl, clientId);
  postBody << "&code_verifier=" << urlEncodeOidc(curl, codeVerifier);

  if (!clientSecret.empty()) {
    postBody << "&client_secret=" << urlEncodeOidc(curl, clientSecret);
  }

  std::string postData = postBody.str();

  responseData->clear();
  responseHeaderData->clear();
  curl_easy_setopt(curl, CURLOPT_URL, tokenEndpoint.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());

  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(
      headers, "Content-Type: application/x-www-form-urlencoded");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  CURLcode res = curl_easy_perform(curl);
  curl_slist_free_all(headers);

  WriteLog(LL_DEBUG,
           "  Token exchange CURLcode: " + std::to_string(res));
  WriteLog(LL_TRACE,
           "  Token exchange response: " + *responseData);

  if (res != CURLE_OK) {
    WriteLog(LL_ERROR,
             "  ERROR: Token exchange request failed with CURLcode: " +
                 std::to_string(res));
    return tokenResponse;
  }

  json responseJson;
  try {
    responseJson = json::parse(*responseData);
  } catch (const json::parse_error& e) {
    WriteLog(LL_ERROR,
             "  ERROR: Failed to parse token exchange response as JSON: " +
                 std::string(e.what()) +
                 " | Raw response: " + *responseData);
    return tokenResponse;
  }

  if (responseJson.contains("error")) {
    std::string error = responseJson["error"].get<std::string>();
    std::string desc  = responseJson.value("error_description", "");
    WriteLog(LL_ERROR,
             "  ERROR: Token endpoint returned error: " + error +
                 " - " + desc);
    return tokenResponse;
  }

  if (responseJson.contains("access_token")) {
    tokenResponse.accessToken =
        responseJson["access_token"].get<std::string>();
    tokenResponse.success = true;
    WriteLog(LL_INFO,
             "  Authorization code token exchange completed successfully");
  }

  if (responseJson.contains("refresh_token")) {
    tokenResponse.refreshToken =
        responseJson["refresh_token"].get<std::string>();
    WriteLog(LL_DEBUG, "  Refresh token received from token endpoint");
  }

  return tokenResponse;
}

TokenResponse refreshAccessToken(
    CURL* curl,
    const std::string& tokenEndpoint,
    const std::string& currentRefreshToken,
    const std::string& clientId,
    const std::string& clientSecret,
    const std::string& scope,
    std::string* responseData,
    std::map<std::string, std::string>* responseHeaderData) {

  TokenResponse tokenResponse;

  std::ostringstream postBody;
  postBody << "grant_type=" << urlEncodeOidc(curl, "refresh_token");
  postBody << "&refresh_token=" << urlEncodeOidc(curl, currentRefreshToken);
  postBody << "&client_id=" << urlEncodeOidc(curl, clientId);

  if (!clientSecret.empty()) {
    postBody << "&client_secret=" << urlEncodeOidc(curl, clientSecret);
  }
  if (!scope.empty()) {
    postBody << "&scope=" << urlEncodeOidc(curl, scope);
  }

  std::string postData = postBody.str();

  responseData->clear();
  responseHeaderData->clear();
  curl_easy_setopt(curl, CURLOPT_URL, tokenEndpoint.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());

  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(
      headers, "Content-Type: application/x-www-form-urlencoded");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  CURLcode res = curl_easy_perform(curl);
  curl_slist_free_all(headers);

  WriteLog(LL_DEBUG,
           "  Refresh token CURLcode: " + std::to_string(res));
  WriteLog(LL_TRACE,
           "  Refresh token response: " + *responseData);

  if (res != CURLE_OK) {
    WriteLog(LL_ERROR,
             "  ERROR: Refresh token request failed with CURLcode: " +
                 std::to_string(res));
    return tokenResponse;
  }

  json responseJson;
  try {
    responseJson = json::parse(*responseData);
  } catch (const json::parse_error& e) {
    WriteLog(LL_ERROR,
             "  ERROR: Failed to parse refresh token response as JSON: " +
                 std::string(e.what()) +
                 " | Raw response: " + *responseData);
    return tokenResponse;
  }

  if (responseJson.contains("error")) {
    std::string error = responseJson["error"].get<std::string>();
    std::string desc  = responseJson.value("error_description", "");
    WriteLog(LL_WARN,
             "  Refresh token rejected (" + error + " - " + desc +
                 "), will require interactive login");
    return tokenResponse;
  }

  if (responseJson.contains("access_token")) {
    tokenResponse.accessToken =
        responseJson["access_token"].get<std::string>();
    tokenResponse.success = true;
    WriteLog(LL_INFO, "  Token refresh completed successfully");
  }

  if (responseJson.contains("refresh_token")) {
    // Some providers rotate refresh tokens on every use.
    tokenResponse.refreshToken =
        responseJson["refresh_token"].get<std::string>();
  } else {
    // Some providers don't rotate refresh tokens. Keep the old one.
    tokenResponse.refreshToken = currentRefreshToken;
  }

  return tokenResponse;
}

} // anonymous namespace


// ============================================================================
// OIDC Auth Code Provider Class
// ============================================================================

class OidcAuthCodeAuthConfig : public TokenCacheAuthProviderBase {
  private:
    std::string oidcDiscoveryUrl;
    std::string clientId;
    std::string clientSecret;
    std::string scope;
    std::string configuredTokenEndpoint;
    std::string redirectUri;
    unsigned short callbackPort;

    // Resolved endpoints (cached after first OIDC discovery call).
    std::string resolvedAuthorizationEndpoint;
    std::string resolvedTokenEndpoint;

    static constexpr int CALLBACK_TIMEOUT_SECONDS = 120;

    std::string resolveTokenEndpoint(
        CURL* curl,
        std::string* responseData,
        std::map<std::string, std::string>* responseHeaderData) {

      if (!configuredTokenEndpoint.empty()) {
        return configuredTokenEndpoint;
      }

      if (!resolvedTokenEndpoint.empty()) {
        return resolvedTokenEndpoint;
      }

      // Perform OIDC discovery to find endpoints.
      OidcEndpoints endpoints = discoverOidcEndpoints(
          curl, oidcDiscoveryUrl, responseData, responseHeaderData);

      resolvedAuthorizationEndpoint = endpoints.authorizationEndpoint;
      resolvedTokenEndpoint         = endpoints.tokenEndpoint;

      return resolvedTokenEndpoint;
    }

    std::string resolveAuthorizationEndpoint(
        CURL* curl,
        std::string* responseData,
        std::map<std::string, std::string>* responseHeaderData) {

      if (!resolvedAuthorizationEndpoint.empty()) {
        return resolvedAuthorizationEndpoint;
      }

      // This will trigger discovery and populate both endpoints.
      resolveTokenEndpoint(curl, responseData, responseHeaderData);
      return resolvedAuthorizationEndpoint;
    }

    std::string attemptRefreshToken(
        CURL* curl,
        std::string* responseData,
        std::map<std::string, std::string>* responseHeaderData) {

      std::string cachedRefreshToken = this->tokenCache->getRefreshToken();
      if (cachedRefreshToken.empty()) {
        WriteLog(LL_DEBUG,
                 "  No cached refresh token available, "
                 "interactive login required");
        return "";
      }

      WriteLog(LL_INFO,
               "  Attempting token refresh using cached refresh token");

      std::string tokenEndpoint =
          resolveTokenEndpoint(curl, responseData, responseHeaderData);
      if (tokenEndpoint.empty()) {
        WriteLog(LL_ERROR,
                 "  ERROR: Cannot resolve token endpoint for refresh");
        return "";
      }

      TokenResponse response = refreshAccessToken(curl,
                                                   tokenEndpoint,
                                                   cachedRefreshToken,
                                                   clientId,
                                                   clientSecret,
                                                   scope,
                                                   responseData,
                                                   responseHeaderData);

      if (response.success) {
        // Update the refresh token in cache if a new one was provided.
        if (!response.refreshToken.empty()) {
          this->tokenCache->setRefreshToken(response.refreshToken);
          writeTokenCache(this->tokenCache.value());
        }
        return response.accessToken;
      }

      WriteLog(LL_WARN,
               "  Refresh token failed or expired, "
               "falling back to interactive login");
      return "";
    }

    std::string performInteractiveLogin(
        CURL* curl,
        std::string* responseData,
        std::map<std::string, std::string>* responseHeaderData) {

      WriteLog(LL_INFO,
               "  Starting interactive OIDC Authorization Code + PKCE flow");

      // Resolve the OIDC endpoints we need.
      std::string authEndpoint =
          resolveAuthorizationEndpoint(curl, responseData, responseHeaderData);
      std::string tokenEndpoint =
          resolveTokenEndpoint(curl, responseData, responseHeaderData);

      if (authEndpoint.empty() || tokenEndpoint.empty()) {
        WriteLog(LL_ERROR,
                 "  ERROR: Could not resolve OIDC endpoints. "
                 "Check oidcDiscoveryUrl or tokenEndpoint configuration.");
        return "";
      }

      // Generate PKCE parameters per RFC 7636.
      std::string codeVerifier  = generateCodeVerifier();
      std::string codeChallenge = generateCodeChallenge(codeVerifier);
      std::string state         = generateState();

      // Build the redirect URI that the IdP will redirect back to.
      std::string actualRedirectUri = redirectUri;
      if (actualRedirectUri.empty()) {
        actualRedirectUri =
            "http://localhost:" + std::to_string(callbackPort) + "/callback";
      }

      // Build the full authorization URL.
      std::ostringstream authUrl;
      authUrl << authEndpoint;
      authUrl << "?response_type=code";
      authUrl << "&client_id=" << urlEncodeOidc(curl, clientId);
      authUrl << "&redirect_uri=" << urlEncodeOidc(curl, actualRedirectUri);
      authUrl << "&code_challenge=" << urlEncodeOidc(curl, codeChallenge);
      authUrl << "&code_challenge_method=S256";
      authUrl << "&state=" << urlEncodeOidc(curl, state);
      if (!scope.empty()) {
        authUrl << "&scope=" << urlEncodeOidc(curl, scope);
      }

      std::string authUrlStr = authUrl.str();
      WriteLog(LL_DEBUG, "  Authorization URL: " + authUrlStr);

      // Prepare to receive the callback.
      CallbackResult callbackResult;

      // Open the authorization URL in the user's default browser.
      WriteLog(LL_INFO,
               "  Opening browser for user authentication...");
      openURLInDefaultBrowser(authUrlStr);

      // Block and wait for the IdP to redirect back to our local server.
      bool received = startCallbackServer(
          callbackPort, callbackResult, CALLBACK_TIMEOUT_SECONDS);

      if (!received) {
        WriteLog(LL_ERROR,
                 "  ERROR: Did not receive authorization callback within " +
                     std::to_string(CALLBACK_TIMEOUT_SECONDS) + " seconds. "
                     "Ensure the redirect URI in the IdP matches: " +
                     actualRedirectUri);
        return "";
      }

      // Check for errors returned by the IdP.
      if (!callbackResult.error.empty()) {
        WriteLog(LL_ERROR,
                 "  ERROR: Authorization failed: " + callbackResult.error +
                     " - " + callbackResult.errorDescription);
        return "";
      }

      // Validate the state parameter to prevent CSRF attacks.
      if (callbackResult.state != state) {
        WriteLog(LL_ERROR,
                 "  ERROR: State mismatch in authorization callback. "
                 "Possible CSRF attack. Expected: " + state +
                     ", Got: " + callbackResult.state);
        return "";
      }

      if (callbackResult.authorizationCode.empty()) {
        WriteLog(LL_ERROR,
                 "  ERROR: No authorization code received in callback");
        return "";
      }

      WriteLog(LL_DEBUG,
               "  Received authorization code, exchanging for tokens");

      // Exchange the authorization code for access and refresh tokens.
      TokenResponse tokenResult = exchangeAuthCodeForTokens(
          curl,
          tokenEndpoint,
          callbackResult.authorizationCode,
          codeVerifier,
          actualRedirectUri,
          clientId,
          clientSecret,
          responseData,
          responseHeaderData);

      if (!tokenResult.success) {
        WriteLog(LL_ERROR,
                 "  ERROR: Failed to exchange authorization code for tokens");
        return "";
      }

      // Cache the refresh token if we received one so that the next
      // connection can use it without requiring browser interaction.
      if (!tokenResult.refreshToken.empty()) {
        this->tokenCache->setRefreshToken(tokenResult.refreshToken);
        this->tokenCache->setAccessToken(tokenResult.accessToken);
        writeTokenCache(this->tokenCache.value());
        WriteLog(LL_DEBUG,
                 "  Cached access and refresh tokens for future use");
      }

      return tokenResult.accessToken;
    }

  public:
    OidcAuthCodeAuthConfig(std::string hostname,
                           unsigned short port,
                           std::string connectionName,
                           std::string oidcDiscoveryUrl,
                           std::string clientId,
                           std::string clientSecret,
                           std::string scope,
                           std::string tokenEndpoint,
                           std::string redirectUri,
                           unsigned short callbackPort)
        : TokenCacheAuthProviderBase(hostname, port, connectionName),
          oidcDiscoveryUrl(std::move(oidcDiscoveryUrl)),
          clientId(std::move(clientId)),
          clientSecret(std::move(clientSecret)),
          scope(std::move(scope)),
          configuredTokenEndpoint(std::move(tokenEndpoint)),
          redirectUri(std::move(redirectUri)),
          callbackPort(callbackPort) {}

    std::string obtainAccessToken(
        CURL* curl,
        std::string* responseData,
        std::map<std::string, std::string>* responseHeaderData) override {

      // Strategy:
      // 1. Try to use the cached refresh token (non-interactive).
      // 2. If refresh fails or no refresh token, do full interactive flow.
      std::string accessToken =
          attemptRefreshToken(curl, responseData, responseHeaderData);

      if (!accessToken.empty()) {
        return accessToken;
      }

      return performInteractiveLogin(curl, responseData, responseHeaderData);
    }

    ~OidcAuthCodeAuthConfig() override = default;
};


// ============================================================================
// Factory Function
// ============================================================================

std::unique_ptr<AuthConfig>
getOidcAuthCodeProvider(std::string hostname,
                        unsigned short port,
                        std::string connectionName,
                        std::string oidcDiscoveryUrl,
                        std::string clientId,
                        std::string clientSecret,
                        std::string oidcScope,
                        std::string tokenEndpoint,
                        std::string redirectUri,
                        unsigned short callbackPort) {

  // Default callback port if not specified.
  if (callbackPort == 0) {
    callbackPort = 8890;
  }

  // Generate a connection name for DSN-less connections so that
  // the token cache layer doesn't get key collisions.
  if (connectionName.empty()) {
    connectionName = clientId + "__" + oidcScope + "__authcode";
  }

  return std::make_unique<OidcAuthCodeAuthConfig>(hostname,
                                                   port,
                                                   connectionName,
                                                   oidcDiscoveryUrl,
                                                   clientId,
                                                   clientSecret,
                                                   oidcScope,
                                                   tokenEndpoint,
                                                   redirectUri,
                                                   callbackPort);
}
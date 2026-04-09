#include "connectionConfig.hpp"
#include <nlohmann/json.hpp>

#include "../util/callbackHelper.hpp"
#include "../util/stringTrim.hpp"
#include "../util/writeLog.hpp"
#include "authProvider/clientCredAuthProvider.hpp"
#include "authProvider/deviceFlowAuthProvider.hpp"
#include "authProvider/externalAuthProvider.hpp"
#include "authProvider/noAuthProvider.hpp"
#include "authProvider/oidcAuthCodeProvider.hpp"


using json = nlohmann::json;

static size_t
curlWriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
  size_t totalSize = size * nmemb;
  s->append(static_cast<char*>(contents), totalSize);
  return totalSize;
}

static size_t
curlHeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
  std::map<std::string, std::string>* responseHeaderData =
      (std::map<std::string, std::string>*)userdata;
  std::string headerData = std::string(buffer, nitems);
  if (headerData.starts_with("HTTP/")) {
    // The HTTP/<version> header is not a key value pair, so
    // it gets some special logic.
    responseHeaderData->insert({"http", headerData});
  } else {
    auto firstColon = headerData.find(':');
    if (firstColon != std::string::npos) {
      std::string key   = headerData.substr(0, firstColon);
      std::string value = headerData.substr(firstColon + 1);
      // The values usually end in \r\n at a minimum, so we need
      // to trim that off.
      trim(value);
      responseHeaderData->insert({key, value});
    }
  }
  // Return the number of bytes consumed to signal success.
  return nitems * size;
}

/**
 * Determines whether the current process can display interactive UI.
 *
 * Returns false when running as:
 * - A Windows Service (Power BI Report Server, SSRS, SQL Agent)
 * - A non-interactive session (scheduled tasks, system accounts)
 *
 * Returns true when running as:
 * - Power BI Desktop
 * - Excel
 * - DBeaver
 * - Any interactive desktop application
 */
static bool canDisplayInteractiveUI() {
  // Check if the process window station allows user interaction.
  HWINSTA hWinStation = GetProcessWindowStation();
  if (hWinStation != nullptr) {
    USEROBJECTFLAGS uof = {};
    if (GetUserObjectInformation(
            hWinStation, UOI_FLAGS, &uof, sizeof(uof), nullptr)) {
      if (!(uof.dwFlags & WSF_VISIBLE)) {
        WriteLog(LL_DEBUG,
                 "  canDisplayInteractiveUI: Window station not visible "
                 "(service/non-interactive)");
        return false;
      }
    }
  }

  // Services run in session 0 on modern Windows (Vista+).
  DWORD sessionId = 0;
  if (ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
    if (sessionId == 0) {
      WriteLog(LL_DEBUG,
               "  canDisplayInteractiveUI: Session 0 detected (service)");
      return false;
    }
  }

  // Check that we can access an input desktop.
  HDESK hDesktop = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
  if (hDesktop == nullptr) {
    WriteLog(LL_DEBUG,
             "  canDisplayInteractiveUI: Cannot open input desktop "
             "(non-interactive)");
    return false;
  }
  CloseDesktop(hDesktop);

  WriteLog(LL_DEBUG,
           "  canDisplayInteractiveUI: Interactive session confirmed");
  return true;
}

ConnectionConfig::ConnectionConfig(std::string hostname,
                                   unsigned short port,
                                   ApiAuthMethod authMethod,
                                   std::string connectionName,
                                   std::string oidcDiscoveryUrl,
                                   std::string clientId,
                                   std::string clientSecret,
                                   std::string oidcScope,
                                   std::string grantType,
                                   std::string tokenEndpoint,
                                   std::string redirectUri,
                                   unsigned short callbackPort) {

  this->hostname       = hostname;
  this->port           = port;
  this->connectionName = connectionName;
  this->authMethod     = authMethod;
  this->tokenEndpoint  = tokenEndpoint;
  this->grantType      = grantType;

  this->curl = nullptr;

  if (hostname.empty()) {
    throw std::invalid_argument("hostname");
  }

  switch (authMethod) {
    case AM_NO_AUTH: {
      this->authConfigPtr = getNoAuthConfigPtr(hostname, port, connectionName);
      break;
    }
    case AM_EXTERNAL_AUTH: {
      this->authConfigPtr =
          getExternalAuthConfigPtr(hostname, port, connectionName);
      break;
    }
    case AM_CLIENT_CRED_AUTH: {
      this->authConfigPtr = getClientCredAuthProvider(hostname,
                                                      port,
                                                      connectionName,
                                                      oidcDiscoveryUrl,
                                                      clientId,
                                                      clientSecret,
                                                      oidcScope,
                                                      grantType,
                                                      tokenEndpoint);
      break;
    }
    case AM_DEVICE_FLOW: {
      this->authConfigPtr = getDeviceFlowAuthProvider(hostname,
                                                      port,
                                                      connectionName,
                                                      oidcDiscoveryUrl,
                                                      clientId,
                                                      clientSecret,
                                                      oidcScope);
      break;
    }
    case AM_OIDC_AUTH_CODE: {
      this->authConfigPtr = getOidcAuthCodeProvider(hostname,
                                                     port,
                                                     connectionName,
                                                     oidcDiscoveryUrl,
                                                     clientId,
                                                     clientSecret,
                                                     oidcScope,
                                                     tokenEndpoint,
                                                     redirectUri,
                                                     callbackPort);
      break;
    }
    case AM_OIDC_AUTO: {
      bool hasClientSecret = !clientSecret.empty();
      bool canShowUI       = canDisplayInteractiveUI();

      if (hasClientSecret && !canShowUI) {
        WriteLog(LL_INFO,
                 "  OIDC Auto: Headless environment detected with client "
                 "secret present. Using Client Credentials flow.");
        this->authConfigPtr = getClientCredAuthProvider(hostname,
                                                        port,
                                                        connectionName,
                                                        oidcDiscoveryUrl,
                                                        clientId,
                                                        clientSecret,
                                                        oidcScope,
                                                        grantType,
                                                        tokenEndpoint);
      } else if (canShowUI) {
        WriteLog(LL_INFO,
                 "  OIDC Auto: Interactive environment detected. "
                 "Using Authorization Code + PKCE flow.");
        this->authConfigPtr = getOidcAuthCodeProvider(hostname,
                                                       port,
                                                       connectionName,
                                                       oidcDiscoveryUrl,
                                                       clientId,
                                                       clientSecret,
                                                       oidcScope,
                                                       tokenEndpoint,
                                                       redirectUri,
                                                       callbackPort);
      } else if (hasClientSecret) {
        WriteLog(LL_INFO,
                 "  OIDC Auto: No UI available but client secret present. "
                 "Using Client Credentials flow.");
        this->authConfigPtr = getClientCredAuthProvider(hostname,
                                                        port,
                                                        connectionName,
                                                        oidcDiscoveryUrl,
                                                        clientId,
                                                        clientSecret,
                                                        oidcScope,
                                                        grantType,
                                                        tokenEndpoint);
      } else {
        WriteLog(LL_ERROR,
                 "  ERROR: OIDC Auto mode cannot determine auth strategy. "
                 "No client secret for headless mode and no UI available "
                 "for interactive mode. Provide a clientSecret or run in "
                 "an interactive session.");
      }
      break;
    }

    default: {
      WriteLog(LL_ERROR,
               "  ERROR: connection config got unimplemented external auth "
               "method value: " +
                   std::to_string(authMethod));
    }
  }
}

ConnectionConfig::~ConnectionConfig() {
  curl_easy_cleanup(this->curl);
}

std::string const ConnectionConfig::getHostname() {
  return this->hostname;
}

unsigned short const ConnectionConfig::getPort() {
  return this->port;
}

ApiAuthMethod const ConnectionConfig::getAuthMethod() {
  return this->authMethod;
}

std::string const ConnectionConfig::getStatementUrl() {
  return (this->hostname) + ":" + std::to_string(port) + "/v1/statement";
}

CURL* ConnectionConfig::createQueryCurlHandle() {
  CURL* handle = curl_easy_init();
  if (!handle) {
    WriteLog(LL_ERROR, "  ERROR: Failed to create CURL handle for query");
    return nullptr;
  }

  // SSL configuration matching the connection handle.
  curl_easy_setopt(
      handle, CURLOPT_SSL_OPTIONS,
      CURLSSLOPT_NATIVE_CA | CURLSSLOPT_NO_REVOKE);

  // Connection reuse within this handle's lifetime.
  curl_easy_setopt(handle, CURLOPT_FRESH_CONNECT, 0L);
  curl_easy_setopt(handle, CURLOPT_FORBID_REUSE, 0L);

  // Timeout matching the connection handle.
  curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, 60000);

  // Compression support.
  curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "gzip, deflate");

  return handle;
}

void ConnectionConfig::refreshAuthIfNeeded() {
  if (this->authConfigPtr->isExpired()) {
    WriteLog(LL_TRACE,
             "  Detected expired authentication. Reauthenticating...");
    // Ensure the connection CURL handle exists for auth refresh.
    if (this->curl == nullptr) {
      this->curl = curl_easy_init();
      curl_easy_setopt(
          this->curl, CURLOPT_SSL_OPTIONS,
          CURLSSLOPT_NATIVE_CA | CURLSSLOPT_NO_REVOKE);
      curl_easy_setopt(this->curl, CURLOPT_TIMEOUT_MS, 60000);
      curl_easy_setopt(
          this->curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate");
      curl_easy_setopt(
          this->curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
      curl_easy_setopt(
          this->curl, CURLOPT_WRITEDATA, &(this->responseData));
      curl_easy_setopt(
          this->curl, CURLOPT_HEADERFUNCTION, curlHeaderCallback);
      curl_easy_setopt(
          this->curl, CURLOPT_HEADERDATA, &(this->responseHeaderData));
    }
    this->responseData.clear();
    this->responseHeaderData.clear();
    this->authConfigPtr->refresh(
        this->curl, &(this->responseData), &(this->responseHeaderData));
  }
}

CURL* ConnectionConfig::getCurl() {
  /*
  Return a curl handle, reset it if needed, and it's ready to go.
  This is used for connection-level operations like auth refresh
  and server version checks. Query execution uses per-statement
  CURL handles created by createQueryCurlHandle().
  */
  if (this->curl == nullptr) {
    this->curl = curl_easy_init();
    // We always want to use SSL.
    curl_easy_setopt(this->curl, CURLOPT_SSL_OPTIONS,
                     CURLSSLOPT_NATIVE_CA | CURLSSLOPT_NO_REVOKE);
    curl_easy_setopt(this->curl, CURLOPT_FRESH_CONNECT, 0L);
    curl_easy_setopt(this->curl, CURLOPT_FORBID_REUSE, 0L);
    // We want to save the response body in a string using a callback.
    curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, &(this->responseData));
    // We want to parse response headers.
    curl_easy_setopt(this->curl, CURLOPT_HEADERFUNCTION, curlHeaderCallback);
    curl_easy_setopt(
        this->curl, CURLOPT_HEADERDATA, &(this->responseHeaderData));
    // Set a timeout on all requests
    curl_easy_setopt(this->curl, CURLOPT_TIMEOUT_MS, 60000);
    // Enable gzip and/or deflate on responses
    curl_easy_setopt(this->curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate");
  }

curlSetup:
  // Clear the previous response data, we do not want to append to it.
  this->responseData.clear();
  // Clear the previous response headers as well
  this->responseHeaderData.clear();

  curl_easy_setopt(this->curl, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(this->curl, CURLOPT_POST, 0L);
  curl_easy_setopt(this->curl, CURLOPT_POSTFIELDS, nullptr);
  curl_easy_setopt(this->curl, CURLOPT_CUSTOMREQUEST, nullptr);

  // Set up any required headers if needed.
  if (this->authConfigPtr->headers.size() > 0) {
    struct curl_slist* headers = nullptr;
    bool shouldLog = getLogLevel() <= LL_DEBUG;
    for (auto pair : this->authConfigPtr->headers) {
      if (shouldLog) {
        WriteLog(LL_DEBUG, "  Setting header: " + pair.first + ": " +
                           pair.second.substr(0, 50));
      }
      std::string nextHeader = pair.first + ": " + pair.second;
      headers                = curl_slist_append(headers, nextHeader.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  }

  // Now that we have a fully configured CURL handle, check if we need to do
  // any required auth steps.
  if (this->authConfigPtr->isExpired()) {
    WriteLog(LL_TRACE,
             "  Detected expired authentication. Reauthenticating...");
    this->authConfigPtr->refresh(
        this->curl, &(this->responseData), &(this->responseHeaderData));
    goto curlSetup;
  }

  return this->curl;
}

long ConnectionConfig::getLastHTTPStatusCode() {
  long httpStatusCode = -1;
  if (this->curl) {
    curl_easy_getinfo(this->curl, CURLINFO_RESPONSE_CODE, &httpStatusCode);
  }
  return httpStatusCode;
}

void ConnectionConfig::disconnect() {
  for (std::function f : this->onDisconnectCallbacks) {
    f(this);
  }
  if (this->curl) {
    curl_easy_cleanup(this->curl);
    this->curl = nullptr;
  }
}

std::string ConnectionConfig::getTrinoServerVersion() {
  CURL* curl = this->getCurl();

  std::string url =
      this->hostname + ":" + std::to_string(this->port) + "/v1/info";

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
    WriteLog(LL_ERROR,
             "Failed to read trino server version: " +
                 std::string(curl_easy_strerror(res)));
    return "";
  }

  json jsonResponse = nlohmann::json::parse(this->responseData);
  return jsonResponse["nodeVersion"]["version"].get<std::string>();
}

void ConnectionConfig::registerDisconnectCallback(
    std::function<void(ConnectionConfig*)> f) {
  this->onDisconnectCallbacks.push_back(f);
}

void ConnectionConfig::unregisterDisconnectCallback(
    std::function<void(ConnectionConfig*)> f) {
  removeCallbackFromVector(this->onDisconnectCallbacks, f);
}
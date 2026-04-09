#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>

#include <curl/curl.h>

#include "apiAuthMethod.hpp"
#include "authProvider/authConfig.hpp"
#include "environmentConfig.hpp"

class ConnectionConfig {
  private:
    std::string hostname;
    unsigned short port;
    std::string connectionName;
    std::string tokenEndpoint;
    std::string grantType;

    ApiAuthMethod authMethod;
    std::unique_ptr<AuthConfig> authConfigPtr;
    std::vector<std::function<void(ConnectionConfig*)>> onDisconnectCallbacks;

    // CURL handle used only for connection-level operations
    // (auth refresh, server version check). Each TrinoQuery
    // creates its own CURL handle for query execution to
    // support parallel queries.
    CURL* curl;

  public:
    ConnectionConfig(std::string hostname,
                     unsigned short port,
                     ApiAuthMethod authMethod,
                     std::string connectionName,
                     std::string oidcDiscoveryUrl,
                     std::string clientId,
                     std::string clientSecret,
                     std::string oidcScope,
                     std::string grantType,
                     std::string tokenEndpoint,
                     std::string redirectUri      = "",
                     unsigned short callbackPort  = 0);

    ~ConnectionConfig();
    std::string const getHostname();
    std::string const getStatementUrl();
    unsigned short const getPort();
    ApiAuthMethod const getAuthMethod();
    CURL* getCurl();
    long getLastHTTPStatusCode();
    void disconnect();
    std::string getTrinoServerVersion();
    void registerDisconnectCallback(std::function<void(ConnectionConfig*)> f);
    void unregisterDisconnectCallback(std::function<void(ConnectionConfig*)> f);

    // Create a new independent CURL handle configured with the same
    // SSL, compression, and timeout settings as the connection handle.
    // Used by TrinoQuery to support parallel query execution.
    CURL* createQueryCurlHandle();

    // Ensure auth token is valid. Call before using auth headers.
    void refreshAuthIfNeeded();

    // Making these public because they're frequently accessed and
    // manipulated external to the ConnectionConfig object
    std::string responseData;
    std::map<std::string, std::string> responseHeaderData;
    std::map<std::string, std::string> getAuthHeaders() {
      return this->authConfigPtr->headers;
    }

    // Default catalog and schema for narrowing metadata queries.
    std::string defaultCatalog = "";
    std::string defaultSchema  = "";
};
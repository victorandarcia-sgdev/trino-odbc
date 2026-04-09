#pragma once

#include <cstdint>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include <curl/curl.h>

#include "TrinoOdbcErrorHandler.hpp"
#include "columnDescription.hpp"
#include "connectionConfig.hpp"

using json = nlohmann::json;

struct UpdateStatus {
    bool gotColumnInfo = false;
    bool gotRowData    = false;
};

enum TrinoQueryPollMode {
  JustOnce,
  UntilNewData,
  UntilColumnsLoaded,
  ToCompletion,
};

// Need to allow a few tests access to private variables
// in this class.
class MemoryReclamationTest;
class FetchGetDataPerformanceTest;
class FetchBindPerformanceTest;

class TrinoQuery {
  private:
    ConnectionConfig* connectionConfig;
    // Each query gets its own CURL handle to support parallel
    // query execution across multiple statements.
    CURL* curlHandle = nullptr;
    // Per-query response buffers so parallel queries don't
    // overwrite each other's data.
    std::string responseData;
    std::map<std::string, std::string> responseHeaderData;
    std::string query = "UNSET";
    std::string queryId;
    std::string infoUri;
    std::string partialCancelUri;
    std::string nextUri;
    std::string status;
    std::vector<json> columnsJson;
    std::vector<json> dataJson;
    std::vector<ColumnDescription> columnDescriptions;
    bool error     = false;
    bool completed = false;
    std::vector<std::function<void(TrinoQuery*)>> onColumnDataCallbacks;
    int64_t rowOffsetPosition = -1;
    UpdateStatus updateSelfFromResponse();
    void onConnectionReset(ConnectionConfig* connectionConfig);
    std::string parseTrinoError(const json& errorJson);
    std::optional<TrinoOdbcErrorHandler::OdbcError> odbcError;

    friend class MemoryReclamationTest;

  public:
    TrinoQuery(ConnectionConfig* connectionConfig);
    ~TrinoQuery();
    void setQuery(std::string query);
    const std::string& getQuery() const;
    void post();
    void cancel();
    void terminate();
    void poll(TrinoQueryPollMode mode);
    const int64_t getCurrentRowCount() const;
    const int64_t getAbsoluteRowCount() const;
    const int16_t getColumnCount();
    const std::vector<ColumnDescription>& getColumnDescriptions();
    const bool getIsCompleted() const;
    void sideloadResponse(json artificialResponse);
    void reset();
    void registerColumnDataChangeCallback(std::function<void(TrinoQuery*)> f);
    const bool hasColumnData() const;
    void checkpointRowPosition(int64_t completedIndex);
    const json& getRowAtIndex(int64_t) const;

    void setQueryId(const std::string& id);
    const std::string& getQueryId() const;
    const bool hasError() const;
    const TrinoOdbcErrorHandler::OdbcError& getError() const;
};

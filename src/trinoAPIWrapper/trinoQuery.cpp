#include <algorithm>
#include <chrono>
#include <curl/curl.h>
#include <functional>
#include <iostream>
#include <map>
#include <ranges>
#include <thread>

#include "TrinoOdbcErrorHandler.hpp"
#include "trinoExceptions.hpp"
#include "trinoQuery.hpp"

#include <stdexcept>

#include "../util/delimKvpHelper.hpp"
#include "../util/stringTrim.hpp"
#include "../util/writeLog.hpp"

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
    responseHeaderData->insert({"http", headerData});
  } else {
    auto firstColon = headerData.find(':');
    if (firstColon != std::string::npos) {
      std::string key   = headerData.substr(0, firstColon);
      std::string value = headerData.substr(firstColon + 1);
      trim(value);
      responseHeaderData->insert({key, value});
    }
  }
  return nitems * size;
}

static int curlDebugCallback(CURL* handle, curl_infotype type,
                             char* data, size_t size, void* userptr) {
  if (type == CURLINFO_TEXT) {
    std::string msg(data, size);
    if (!msg.empty() && msg.back() == '\n') {
      msg.pop_back();
    }
    WriteLog(LL_DEBUG, "  CURL: " + msg);
  }
  return 0;
}

// How long should we poll between requests to Trino's nextUri?
int API_POLL_INTERVAL_MS = 25;

TrinoQuery::TrinoQuery(ConnectionConfig* connectionConfig) {
  this->connectionConfig = connectionConfig;
  this->connectionConfig->registerDisconnectCallback(
      std::bind(&TrinoQuery::onConnectionReset, this, std::placeholders::_1));
  this->curlHandle = this->connectionConfig->createQueryCurlHandle();
}

TrinoQuery::~TrinoQuery() {
  this->connectionConfig->unregisterDisconnectCallback(
      std::bind(&TrinoQuery::onConnectionReset, this, std::placeholders::_1));
  if (this->curlHandle) {
    curl_easy_cleanup(this->curlHandle);
    this->curlHandle = nullptr;
  }
}

std::string TrinoQuery::parseTrinoError(const json& errorJson) {
  std::ostringstream oss;

  if (!(errorJson.contains("errorName") && errorJson.contains("errorType") &&
        errorJson.contains("errorCode"))) {
    return oss.str();
  }

  std::string errorName = errorJson["errorName"].get<std::string>();
  std::string errorType = errorJson["errorType"].get<std::string>();
  int errorCode         = errorJson["errorCode"].get<int>();

  oss << "Trino Error Information(queryId:" << getQueryId() << ")\n"
      << "\tError Type: " << errorType << "\n"
      << "\tError Code: " << errorName << "(" << errorCode << ")\n";

  if (errorJson.contains("message")) {
    oss << "\tMessage: " << errorJson["message"].get<std::string>() << "\n";
  }

  if (errorJson.contains("failureInfo")) {
    auto failureInfo = errorJson["failureInfo"];

    if (failureInfo.contains("stack")) {
      oss << "\tStack:\n";
      for (const auto& frame : failureInfo["stack"]) {
        oss << "\t\t" << frame.get<std::string>() << "\n";
      }
    }

    if (failureInfo.contains("cause") &&
        failureInfo["cause"].contains("type") &&
        failureInfo["cause"].contains("stack")) {
      oss << "\tCaused By: " << failureInfo["cause"]["type"] << "\n";
      for (const auto& frame : failureInfo["cause"]["stack"]) {
        oss << "\t\t" << frame.get<std::string>() << "\n";
      }
    }
  }

  if (errorJson.contains("stack")) {
    oss << "\tTop Stack:\n";
    for (const auto& frame : errorJson["stack"]) {
      oss << "\t\t" << frame.get<std::string>() << "\n";
    }
  }

  return oss.str();
}

UpdateStatus TrinoQuery::updateSelfFromResponse() {
  WriteLog(LL_TRACE, "  Entering TrinoQuery::updateSelfFromResponse");
  json response_json = json::parse(this->responseData);
  WriteLog(LL_DEBUG, "  Response is Parsed");
  UpdateStatus updateStatus;

  if (response_json.contains("error")) {
    this->error = true;

    odbcError = TrinoOdbcErrorHandler::FromTrinoJson(response_json["error"],
                                                     getQueryId());

    WriteLog(LL_ERROR,
             TrinoOdbcErrorHandler::OdbcErrorToString(odbcError.value(), true));
  }

  if (response_json.contains("queryId")) {
    setQueryId(response_json["queryId"]);
  } else if (response_json.contains("id")) {
    setQueryId(response_json["id"]);
  }

  if (response_json.contains("infoUri")) {
    this->infoUri = response_json["infoUri"];
  } else {
    this->infoUri.clear();
  }

  if (response_json.contains("partialCancelUri")) {
    this->partialCancelUri = response_json["partialCancelUri"];
  } else {
    this->partialCancelUri.clear();
  }

  if (response_json.contains("nextUri")) {
    this->nextUri = response_json["nextUri"];
  } else {
    this->completed = true;
    this->nextUri.clear();
  }

  if (response_json.contains("columns") and this->columnDescriptions.empty()) {
    WriteLog(LL_TRACE, "  Parsing column info from TrinoQuery data result");
    this->columnsJson = response_json["columns"];
    std::vector<ColumnDescription> columnDescriptions;
    std::transform(this->columnsJson.begin(),
                   this->columnsJson.end(),
                   std::back_inserter(columnDescriptions),
                   [](const json& json) { return ColumnDescription(json); });
    this->columnDescriptions   = columnDescriptions;
    updateStatus.gotColumnInfo = true;
    for (std::function f : this->onColumnDataCallbacks) {
      f(this);
    }
  }

  if (response_json.contains("data")) {
    WriteLog(LL_TRACE, "  Adding data to TrinoQuery data result");
    updateStatus.gotRowData = true;
    size_t existingRows     = this->dataJson.size();
    size_t newRows          = response_json["data"].size();
    this->dataJson.reserve(existingRows + newRows);
    this->dataJson.insert(this->dataJson.end(),
                          response_json["data"].begin(),
                          response_json["data"].end());
  }

  if (response_json.contains("stats")) {
    if (response_json["stats"].contains("state")) {
      this->status = response_json["stats"]["state"];
    }
  }

  WriteLog(LL_TRACE, "  Exiting TrinoQuery::updateSelfFromResponse");
  return updateStatus;
}

void TrinoQuery::onConnectionReset(ConnectionConfig* connectionConfig) {
  this->terminate();
}

void TrinoQuery::setQuery(std::string query) {
  this->query = query;
}

const std::string& TrinoQuery::getQuery() const {
  return this->query;
}

void TrinoQuery::post() {
  // Ensure auth is current before posting.
  this->connectionConfig->refreshAuthIfNeeded();

  CURL* curl = this->curlHandle;

  // Clear previous response data.
  this->responseData.clear();
  this->responseHeaderData.clear();

  // Configure write callbacks to use our own buffers.
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &(this->responseData));
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curlHeaderCallback);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &(this->responseHeaderData));

  std::string statementURL = this->connectionConfig->getStatementUrl();
  curl_easy_setopt(curl, CURLOPT_URL, statementURL.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query.c_str());

  // Set auth headers.
  struct curl_slist* headers = nullptr;
  bool shouldLog = getLogLevel() <= LL_DEBUG;
  for (auto pair : this->connectionConfig->getAuthHeaders()) {
    std::string h = pair.first + ": " + pair.second;
    if (shouldLog) {
      WriteLog(LL_DEBUG, "  Setting header: " + pair.first + ": " +
                         pair.second.substr(0, 50));
    }
    headers = curl_slist_append(headers, h.c_str());
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  CURLcode res = curl_easy_perform(curl);

  // Reset CURL back to GET mode after POST.
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(curl, CURLOPT_POST, 0L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, nullptr);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, nullptr);

  // Free headers.
  if (headers) {
    curl_slist_free_all(headers);
  }

  if (res != CURLE_OK) {
    WriteLog(LL_ERROR, std::string("CURL error: ") + curl_easy_strerror(res));
  }

  long httpStatusCode = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpStatusCode);

  if (httpStatusCode == 200 and res == CURLE_OK) {
    updateSelfFromResponse();
    if (this->nextUri.empty()) {
      WriteLog(LL_ERROR,
               "  Error POSTing query. No next_uri in response " +
                   std::to_string(httpStatusCode));
      throw std::runtime_error("No NextURI in Trino POST response");
    }
  } else {
    WriteLog(LL_ERROR,
             "  Error POSTing query. CURL status code was " +
                 std::to_string(httpStatusCode));
    throw std::runtime_error("Unexpected Trino POST status: " +
                             std::to_string(httpStatusCode));
  }
}

void TrinoQuery::poll(TrinoQueryPollMode mode) {
  if (this->completed) {
    return;
  }

  int pollCount = 1;
  while (!this->completed) {
    this->responseData.clear();
    this->responseHeaderData.clear();

    CURL* curl = this->curlHandle;

    // Configure write callbacks to use our own buffers.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &(this->responseData));
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curlHeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &(this->responseHeaderData));

    curl_easy_setopt(curl, CURLOPT_URL, this->nextUri.c_str());
    if (getLogLevel() <= LL_TRACE) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curlDebugCallback);
    } else {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    }

    WriteLog(LL_DEBUG, "  Poll attempt " + std::to_string(pollCount) +
                       " | nextUri: " + this->nextUri);

    // Ensure auth is current before polling.
    this->connectionConfig->refreshAuthIfNeeded();

    // Build poll-specific headers.
    struct curl_slist* pollHeaders = nullptr;
    for (auto pair : this->connectionConfig->getAuthHeaders()) {
      std::string h = pair.first + ": " + pair.second;
      pollHeaders = curl_slist_append(pollHeaders, h.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, pollHeaders);

    // Force a clean GET with no body.
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 0L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, nullptr);

    CURLcode res = curl_easy_perform(curl);

    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    WriteLog(LL_DEBUG, "  Poll result: CURLcode=" + std::to_string(res) +
                       " HTTP=" + std::to_string(httpCode));

    if (res == CURLE_OK && httpCode != 200) {
      WriteLog(LL_ERROR, "  Poll non-200 response body: " +
                         this->responseData);
    }

    UpdateStatus updateStatus;
    if (res == CURLE_OK && httpCode == 200) {
      updateStatus = updateSelfFromResponse();
    } else if (res != CURLE_OK) {
      WriteLog(LL_ERROR,
               "  Poll CURL error: " + std::string(curl_easy_strerror(res)) +
                   " (code " + std::to_string(res) + ")");
    }

    // Free poll headers.
    if (pollHeaders) {
      curl_slist_free_all(pollHeaders);
      pollHeaders = nullptr;
    }

    if (mode == JustOnce) {
      break;
    }
    if (mode == UntilColumnsLoaded && not this->columnsJson.empty()) {
      break;
    }
    if (mode == UntilNewData and not this->completed) {
      if (updateStatus.gotRowData) {
        break;
      }
    }

    if (updateStatus.gotRowData or updateStatus.gotColumnInfo) {
      pollCount = 0;
    } else {
      std::this_thread::sleep_for(
          std::chrono::milliseconds(pollCount * API_POLL_INTERVAL_MS));
    }
    pollCount++;
  }
}

/*
 Canceling a query causes it to gracefully stop.
 It may return a few more rows before finishing up,
 but it will attempt to stop before completion.
 This is accomplished by sending a DELETE to the
 partialCancelUri.

 NOTE: Testing showed this wasn't actually cancelling
 queries for me. TrinoQuery::terminate() worked better.
*/
void TrinoQuery::cancel() {
  if (this->partialCancelUri.size() > 0) {
    CURL* curl = this->curlHandle;
    curl_easy_setopt(curl, CURLOPT_URL, this->partialCancelUri.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

    CURLcode res = curl_easy_perform(curl);
    UpdateStatus updateStatus;
    if (res == CURLE_OK) {
      WriteLog(LL_WARN, "Query Cancellation Sent. Polling to completion");
      this->poll(ToCompletion);
    }
  }
}

/*
 Terminating a query causes it to stop running ASAP.
 This is accomplished by sending a DELETE to the nextUri.
*/
void TrinoQuery::terminate() {
  if (not this->getIsCompleted() and this->nextUri.size() > 0) {
    CURL* curl = this->curlHandle;
    curl_easy_setopt(curl, CURLOPT_URL, this->nextUri.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

    // Set auth headers for the DELETE request.
    struct curl_slist* headers = nullptr;
    for (auto pair : this->connectionConfig->getAuthHeaders()) {
      std::string h = pair.first + ": " + pair.second;
      headers = curl_slist_append(headers, h.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    // Free headers.
    if (headers) {
      curl_slist_free_all(headers);
    }

    // Reset custom request method.
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, nullptr);

    UpdateStatus updateStatus;
    if (res == CURLE_OK) {
      WriteLog(LL_WARN, "Query Termination Sent. Resetting query object");
      this->reset();
      return;
    } else {
      throw std::runtime_error("Trino query termination failed");
    }
  }
}

const int64_t TrinoQuery::getAbsoluteRowCount() const {
  if (this->completed) {
    return this->getCurrentRowCount();
  } else {
    return -1;
  }
}

const int64_t TrinoQuery::getCurrentRowCount() const {
  return (this->rowOffsetPosition + 1) + this->dataJson.size();
}

const int16_t TrinoQuery::getColumnCount() {
  if (this->columnDescriptions.empty()) {
    this->poll(UntilColumnsLoaded);
  }
  return static_cast<int16_t>(this->columnsJson.size());
}

const std::vector<ColumnDescription>& TrinoQuery::getColumnDescriptions() {
  if (this->columnDescriptions.empty()) {
    this->poll(UntilColumnsLoaded);
  }
  return this->columnDescriptions;
}

const bool TrinoQuery::getIsCompleted() const {
  return this->completed;
}

void TrinoQuery::sideloadResponse(json artificialResponse) {
  /*
   The sideload method makes it easy to drop a response in
   that doesn't actually come from the database, such as
   the type information for supported types for the driver.
   */
  this->responseData = artificialResponse.dump();
  this->updateSelfFromResponse();
}

/*
  Reset happens when an application wants to reuse a cursor with
  a different query. We need to clear out the results such that
  this is ready to be reused.
*/
void TrinoQuery::reset() {
  WriteLog(LL_TRACE, "  TrinoQuery is resetting");
  this->query.clear();
  this->queryId.clear();
  this->infoUri.clear();
  this->partialCancelUri.clear();
  this->nextUri.clear();
  this->status.clear();
  this->columnsJson.clear();
  this->dataJson.clear();
  this->columnDescriptions.clear();
  this->error             = false;
  this->completed         = false;
  this->rowOffsetPosition = -1;
  this->odbcError         = std::nullopt;
  this->responseData.clear();
  this->responseHeaderData.clear();
}

void TrinoQuery::registerColumnDataChangeCallback(
    std::function<void(TrinoQuery*)> f) {
  this->onColumnDataCallbacks.push_back(f);
}

const bool TrinoQuery::hasColumnData() const {
  return not this->columnDescriptions.empty();
}

void TrinoQuery::checkpointRowPosition(int64_t completedIndex) {
  if (completedIndex < 0) {
    return;
  }
  int64_t dataJsonPosition = completedIndex;
  if (this->rowOffsetPosition > -1) {
    dataJsonPosition -= (this->rowOffsetPosition + 1);
  }

  if (dataJsonPosition == static_cast<int64_t>(dataJson.size()) - 1) {
    dataJson.clear();
  } else {
    dataJson.erase(dataJson.begin(),
                   dataJson.begin() +
                       static_cast<std::vector<int64_t>::difference_type>(
                           dataJsonPosition));
  }
  this->rowOffsetPosition = completedIndex;
}

const json& TrinoQuery::getRowAtIndex(int64_t index) const {
  if (this->rowOffsetPosition > -1) {
    return this->dataJson[static_cast<std::vector<json>::size_type>(
        index - (this->rowOffsetPosition + 1))];
  } else {
    return this->dataJson[static_cast<std::vector<json>::size_type>(index)];
  }
}

void TrinoQuery::setQueryId(const std::string& id) {
  queryId = id;
}

const std::string& TrinoQuery::getQueryId() const {
  return queryId;
}

const bool TrinoQuery::hasError() const {
  if (odbcError.has_value()) {
    return true;
  } else {
    return false;
  }
}

const TrinoOdbcErrorHandler::OdbcError& TrinoQuery::getError() const {
  return odbcError.value();
};
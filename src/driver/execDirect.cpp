#include "../util/windowsLean.hpp"
#include <sql.h>
#include <string.h>

#include "../trinoAPIWrapper/trinoQuery.hpp"
#include "../util/stringFromChar.hpp"
#include "../util/writeLog.hpp"
#include "handles/statementHandle.hpp"

SQLRETURN SQL_API SQLExecDirect(SQLHSTMT StatementHandle,
                                _In_reads_opt_(TextLength)
                                    SQLCHAR* StatementText,
                                SQLINTEGER TextLength) {
  WriteLog(LL_TRACE, "Entering SQLExecDirect");

  if (not StatementText) {
    WriteLog(LL_ERROR, " ERROR: No StatementText defined for query");
    return SQL_ERROR;
  }

  Statement* statementPtr = reinterpret_cast<Statement*>(StatementHandle);

  try {
    Statement* statement  = reinterpret_cast<Statement*>(StatementHandle);
    std::string queryText = stringFromChar(StatementText, TextLength);
    WriteLog(LL_DEBUG, "  Query: " + queryText);

    TrinoQuery* trinoQuery = statement->trinoQuery;

    // If there is already an active query on this statement,
    // reset it before executing the new one. This handles the
    // pattern where applications like PBI Report Server execute
    // a query, fetch a few rows for schema validation, then
    // re-execute the same query to fetch all data.
    if (statement->executed) {
      WriteLog(LL_DEBUG,
               "  Statement already executed. Resetting before re-execution.");
      statement->reset();
    }

    WriteLog(LL_DEBUG, "  Setting Query");
    trinoQuery->setQuery(queryText);
    WriteLog(LL_DEBUG, "  POSTing Query");
    trinoQuery->post();
    WriteLog(LL_DEBUG, "  Setting to executed");
    statement->executed = true;
    return SQL_SUCCESS;
  } catch (const std::exception& ex) {
    WriteLog(LL_ERROR,
             "  ERROR: Exception thrown during SQLExecDirect: " +
                 std::string(ex.what()));
    ErrorInfo errorInfo("Exception thrown during SQLExecDirect: " +
                            std::string(ex.what()),
                        "HY000");
    statementPtr->setError(errorInfo);
    return SQL_ERROR;
  }
}

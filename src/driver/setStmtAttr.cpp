#include "../util/windowsLean.hpp"
#include <sql.h>
#include <sqlext.h>

#include "../trinoAPIWrapper/trinoQuery.hpp"
#include "../util/writeLog.hpp"
#include "constants/statementAttrs.hpp"
#include "handles/statementHandle.hpp"

SQLRETURN SQL_API SQLSetStmtAttr(SQLHSTMT StatementHandle,
                                 SQLINTEGER Attribute,
                                 _In_reads_(_Inexpressible_(StringLength))
                                     SQLPOINTER Value,
                                 SQLINTEGER StringLength) {
  WriteLog(LL_TRACE, "Entering SQLSetStmtAttr");
  Statement* statement = reinterpret_cast<Statement*>(StatementHandle);

  WriteLog(LL_TRACE, "  Setting attribute: " + std::to_string(Attribute));
  switch (Attribute) {
    case SQL_ATTR_ROWS_FETCHED_PTR: { // 26
      SQLULEN* rowsProcessedPtr = static_cast<SQLULEN*>(Value);
      WriteLog(LL_TRACE, std::format("  Attribute value is set to {}", Value));
      Descriptor* impRowDesc             = statement->impRowDesc;
      impRowDesc->Field_RowsProcessedPtr = rowsProcessedPtr;
      break;
    }
    case SQL_ATTR_DEFAULT_FETCH_POLL_MODE: { // 1002
      SQLINTEGER pollModeInt = *reinterpret_cast<SQLINTEGER*>(Value);
      WriteLog(LL_TRACE,
               "  Attribute value is set to " + std::to_string(pollModeInt));
      statement->fetchPollMode = static_cast<TrinoQueryPollMode>(pollModeInt);
      break;
    }
    case SQL_ATTR_QUERY_TIMEOUT: { // 0
      // Report Server sets query timeout. Accept but ignore.
      WriteLog(LL_TRACE, "  Query timeout requested (accepted, not enforced)");
      break;
    }
    case SQL_ATTR_MAX_ROWS: { // 1
      // Accept but ignore max rows limit.
      WriteLog(LL_TRACE, "  Max rows requested (accepted, not enforced)");
      break;
    }
    case SQL_ATTR_NOSCAN: { // 2
      // Accept but ignore - controls escape clause scanning.
      break;
    }
    case SQL_ATTR_MAX_LENGTH: { // 3
      // Accept but ignore.
      break;
    }
    case SQL_ATTR_CURSOR_TYPE: { // 6
      // Only forward-only cursors supported. Accept silently.
      break;
    }
    case SQL_ATTR_CONCURRENCY: { // 7
      // Read-only concurrency. Accept silently.
      break;
    }
    case SQL_ATTR_METADATA_ID: { // 10014
      // Controls whether catalog function args are identifiers.
      // Accept but ignore.
      break;
    }
    default: {
      WriteLog(LL_WARN,
               "  WARNING: Attribute " + std::to_string(Attribute) +
                   " is not implemented - returning success with info");
      return SQL_SUCCESS_WITH_INFO;
    }
  }

  return SQL_SUCCESS;
}

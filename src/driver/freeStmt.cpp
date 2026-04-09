#include "../util/windowsLean.hpp"
#include <sql.h>
#include <sqlext.h>

#include "../util/writeLog.hpp"
#include "handles/statementHandle.hpp"

SQLRETURN SQL_API SQLFreeStmt(SQLHSTMT StatementHandle, SQLUSMALLINT Option) {
  WriteLog(LL_TRACE, "Entering SQLFreeStmt");
  Statement* stmt = reinterpret_cast<Statement*>(StatementHandle);
  switch (Option) {
    case SQL_CLOSE: {
      WriteLog(
          LL_TRACE,
          "  Closing statement with SQL_CLOSE. The statement may be reused.");
      stmt->reset();
      return SQL_SUCCESS;
    }
    case SQL_DROP: {
      WriteLog(LL_WARN, "  Closing statement with SQL_DROP (deprecated)");
      return SQLFreeHandle(SQL_HANDLE_STMT, StatementHandle);
    }
    case SQL_UNBIND: {
      WriteLog(LL_TRACE, "  Unbinding columns with SQL_UNBIND");
      // Reset all bound column buffers in the row descriptor.
      Descriptor* rowDesc = stmt->getRowDescriptor();
      rowDesc->reset();
      return SQL_SUCCESS;
    }
    case SQL_RESET_PARAMS: {
      WriteLog(LL_TRACE, "  Resetting parameters with SQL_RESET_PARAMS");
      // Reset the parameter descriptor. We don't support parameters
      // yet, but returning success prevents applications from aborting.
      Descriptor* paramDesc = stmt->getParamDescriptor();
      paramDesc->reset();
      return SQL_SUCCESS;
    }
    default: {
      WriteLog(LL_ERROR, "  ERROR: Unknown option in SQLFreeStmt");
      return SQL_ERROR;
    }
  }
}

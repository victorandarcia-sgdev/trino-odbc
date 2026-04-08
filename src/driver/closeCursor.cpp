#include "../util/windowsLean.hpp"
#include <sql.h>
#include <sqlext.h>

#include "../util/writeLog.hpp"
#include "handles/statementHandle.hpp"

SQLRETURN SQL_API SQLCloseCursor(SQLHSTMT StatementHandle) {
  WriteLog(LL_TRACE, "Entering SQLCloseCursor");
  if (!StatementHandle) {
    return SQL_INVALID_HANDLE;
  }
  Statement* statement = reinterpret_cast<Statement*>(StatementHandle);
  // Close the cursor by resetting the statement. This terminates
  // any in-flight Trino query and prepares the statement for reuse.
  // Applications like PBI Report Server call this between a schema
  // validation fetch and the full data fetch.
  statement->reset();
  return SQL_SUCCESS;
}

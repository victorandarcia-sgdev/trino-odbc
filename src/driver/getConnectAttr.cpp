#include "../util/windowsLean.hpp"
#include <sql.h>
#include <sqlext.h>

#include "../util/valuePtrHelper.hpp"
#include "../util/writeLog.hpp"


SQLRETURN SQL_API SQLGetConnectAttr(
    SQLHDBC ConnectionHandle,
    SQLINTEGER Attribute,
    _Out_writes_opt_(_Inexpressible_(BufferLength)) SQLPOINTER Value,
    SQLINTEGER BufferLength,
    _Out_opt_ SQLINTEGER* StringLengthPtr) {
  WriteLog(LL_TRACE, "Entering SQLGetConnectAttr");
  WriteLog(LL_TRACE,
           "  Application is requesting connection attribute: " +
               std::to_string(Attribute));
  switch (Attribute) {
    case (SQL_ATTR_CONNECTION_DEAD): {
    }
    case (SQL_ATTR_CURRENT_CATALOG): {
      // Return an empty string to show that no catalog is assigned.
      // I'm not sure if you can set a specific catalog at the connection level.
      writeNullTermStringToPtr(Value, "system", StringLengthPtr);
      break;
    }
    case SQL_ATTR_CONNECTION_TIMEOUT: { // 113
      // Report Server asks for this. Return 0 = no timeout.
      *((SQLUINTEGER*)Value) = 0;
      break;
    }
    case SQL_ATTR_LOGIN_TIMEOUT: { // 103
      // Return 0 = no timeout.
      *((SQLUINTEGER*)Value) = 0;
      break;
    }
    case SQL_ATTR_AUTOCOMMIT: { // 102
      // Trino doesn't support transactions. Always autocommit.
      *((SQLUINTEGER*)Value) = SQL_AUTOCOMMIT_ON;
      break;
    }
    case SQL_ATTR_TXN_ISOLATION: { // 108
      // Return read uncommitted since Trino has no transactions.
      *((SQLUINTEGER*)Value) = SQL_TXN_READ_UNCOMMITTED;
      break;
    }
    default: {
      WriteLog(LL_WARN,
               "  WARNING: Application is requesting unimplemented connection "
               "attribute: " +
                   std::to_string(Attribute));
      return SQL_SUCCESS_WITH_INFO;
    }

  }
  return SQL_SUCCESS;
}

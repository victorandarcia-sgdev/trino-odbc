#include <windows.h>

#include <gtest/gtest.h>
#include <sql.h>
#include <sqlext.h>

#include "../constants.hpp"
#include "../fixtures/sqlDriverConnectFixture.hpp"

class GetInfoTest : public SQLDriverConnectFixture {};

TEST_F(GetInfoTest, GetODBCVersion) {
  unsigned char buf[16];
  // Put some nonsense into the char array as a test.
  std::fill_n(buf, 16, 'A');
  SQLSMALLINT bufferLen        = 16;
  SQLSMALLINT StrLen_or_IndPtr = 0;
  SQLRETURN ret                = SQLGetInfo(
      this->hDbc, SQL_DRIVER_ODBC_VER, buf, bufferLen, &StrLen_or_IndPtr);

  // The string should be 5 long. The spec says the string length
  // is returned _excluding_ the null-termination character.
  ASSERT_EQ(StrLen_or_IndPtr, 5);
  // We can use the returned length to construct a proper string
  // from the char array to do this comparison.
  std::string odbcVer(buf, buf + StrLen_or_IndPtr);
  ASSERT_EQ(odbcVer, std::string("03.80"));
}

TEST_F(GetInfoTest, GetTrinoDBMSName) {
  unsigned char buf[16];
  // Put some nonsense into the char array as a test.
  std::fill_n(buf, 16, 'A');
  SQLSMALLINT bufferLen        = 16;
  SQLSMALLINT StrLen_or_IndPtr = 0;
  SQLRETURN ret =
      SQLGetInfo(this->hDbc, SQL_DBMS_NAME, buf, bufferLen, &StrLen_or_IndPtr);

  // The string should be 5 long. The spec says the string length
  // is returned _excluding_ the null-termination character.
  ASSERT_EQ(StrLen_or_IndPtr, 5);

  // We can use the returned length to construct a proper string
  // from the char array to do this comparison.
  std::string dbmsName(buf, buf + StrLen_or_IndPtr);
  ASSERT_EQ(dbmsName, std::string("Trino"));
}
TEST_F(GetInfoTest, GetTrinoDBMSVersion) {
  unsigned char buf[16];
  // Put some nonsense into the char array as a test.
  std::fill_n(buf, 16, 'A');
  SQLSMALLINT bufferLen        = 16;
  SQLSMALLINT StrLen_or_IndPtr = 0;
  SQLRETURN ret =
      SQLGetInfo(this->hDbc, SQL_DBMS_VER, buf, bufferLen, &StrLen_or_IndPtr);

  // SQL_DBMS_VER now returns a static version string to avoid
  // triggering network calls during early connection setup.
  // The format is ##.##.#### as required by the ODBC spec.
  ASSERT_EQ(StrLen_or_IndPtr, 10);

  std::string dbmsVers(buf, buf + StrLen_or_IndPtr);
  ASSERT_EQ(dbmsVers, std::string("00.00.0001"));
}

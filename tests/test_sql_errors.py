import unittest
from scanner.sqli.errors import SQL_ERRORS

class TestSQLErrors(unittest.TestCase):
    
    def test_sql_errors(self):
        """Test if the SQL_ERRORS dictionary contains the expected error patterns for each database."""

        # Expected error patterns for MySQL
        mysql_errors = [
            "you have an error in your sql syntax;",
            "warning: mysql",
            "unclosed quotation mark after the character string"
        ]
        self.assertTrue(all(error in SQL_ERRORS["MySQL"] for error in mysql_errors), "MySQL errors are missing or incorrect.")
        
        # Expected error patterns for PostgreSQL
        postgres_errors = [
            "pg_query():",
            "pg_exec()",
            "postgresql"
        ]
        self.assertTrue(all(error in SQL_ERRORS["PostgreSQL"] for error in postgres_errors), "PostgreSQL errors are missing or incorrect.")
        
        # Expected error patterns for SQLServer
        sqlserver_errors = [
            "microsoft sql server",
            "sql server",
            "unclosed quotation mark"
        ]
        self.assertTrue(all(error in SQL_ERRORS["SQLServer"] for error in sqlserver_errors), "SQLServer errors are missing or incorrect.")
        
        # Expected error patterns for Oracle
        oracle_errors = [
            "quoted string not properly terminated",
            "oracle error"
        ]
        self.assertTrue(all(error in SQL_ERRORS["Oracle"] for error in oracle_errors), "Oracle errors are missing or incorrect.")
        
        # Expected error patterns for SQLite
        sqlite_errors = [
            "sqlite3::exception",
            "sqlite error"
        ]
        self.assertTrue(all(error in SQL_ERRORS["SQLite"] for error in sqlite_errors), "SQLite errors are missing or incorrect.")

if __name__ == '__main__':
    unittest.main()

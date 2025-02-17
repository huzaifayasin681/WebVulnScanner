SQL_ERRORS = {
    "MySQL": [
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "mysql_fetch_array()",
        "sql syntax error",
        "unknown column",
        "duplicate entry",
        "invalid query",
        "incorrect syntax near"
    ],
    "PostgreSQL": [
        "pg_query():",
        "pg_exec()",
        "postgresql",
        "syntax error at or near",
        "invalid byte sequence for encoding",
        "duplicate key value violates unique constraint",
        "could not execute query",
        "missing FROM-clause entry for table"
    ],
    "SQLServer": [
        "microsoft sql server",
        "sql server",
        "unclosed quotation mark",
        "SQL syntax error",
        "Invalid object name",
        "Login failed for user",
        "cannot resolve the collation conflict",
        "subquery returned more than 1 value"
    ],
    "Oracle": [
        "quoted string not properly terminated",
        "oracle error",
        "ORA-",
        "ORA-00936: missing expression",
        "ORA-01722: invalid number",
        "ORA-00001: unique constraint violated",
        "ORA-01861: literal does not match format string"
    ],
    "SQLite": [
        "sqlite3::exception",
        "sqlite error",
        "SQLITE_ERROR",
        "SQLITE_BUSY",
        "SQLite logic error",
        "syntax error",
        "unknown column"
    ],
    "MariaDB": [
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unknown column",
        "duplicate entry",
        "mariadb"
    ],
    "MongoDB": [
        "exception in user code",
        "errmsg",
        "db.command failed",
        "not authorized on",
        "E11000 duplicate key error collection",
        "invalid operator"
    ],
    "DB2": [
        "SQLSTATE",
        "SQL0803N",
        "SQL0901N",
        "SQL0902N",
        "SQL0204N: 'TABLE' is an undefined name"
    ],
    "Redis": [
        "ERR wrong number of arguments",
        "ERR syntax error",
        "BUSY Redis is loading the dataset",
        "READONLY You can't write against a read-only slave."
    ],
    "CouchDB": [
        "error",
        "query failed",
        "invalid JSON",
        "conflict",
        "resource_not_found",
        "db_update_conflict"
    ],
    "Cassandra": [
        "SyntaxException",
        "Invalid query",
        "NoHostAvailableException",
        "ReadTimeoutException",
        "WriteTimeoutException"
    ],
    # Custom error messages from applications
    "CustomErrors": [
        "unexpected token",
        "query failed",
        "invalid input",
        "query timeout",
        "invalid query structure",
        "incorrect argument",
        "column not found",
        "missing parameter"
    ]
}

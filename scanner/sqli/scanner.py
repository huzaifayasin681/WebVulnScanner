### scanner.py

# Main SQLI scanner logic
import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .payloads import SQL_PAYLOADS, get_random_payloads
from .errors import SQL_ERRORS
from .forms import extract_forms
import requests

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
            if input_name is None:
                continue  # Skip inputs without a name attribute

            # Select a subset of payloads dynamically
            injected_payloads = get_random_payloads(SQL_PAYLOADS, num_payloads=5)

            for payload in injected_payloads:
                # Prepare the payload data
                data = {field["name"]: field["value"] + payload if field["name"] == input_name else field["value"] for field in inputs}
                logging.debug(f"Submitting payload: {payload} in field: {input_name}")

                try:
                    if method == "post":
                        injected_response = session.post(action, data=data, timeout=10, verify=False)
                    else:
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
                                break
                        else:
                            continue
                        break
                except requests.exceptions.RequestException as e:
                    logging.error(f"Error occurred while submitting form to {action}: {e}")
                    continue

    # Additionally, scan URL parameters (GET requests)
    query_params = parse_qs(parsed_url.query)
    if query_params:
        logging.info(f"Found {len(query_params)} parameter(s) to scan for SQLi in URL.")
        for param, original_values in query_params.items():
            injected_payloads = get_random_payloads(SQL_PAYLOADS, num_payloads=5)
            for payload in injected_payloads:
                injected_params = query_params.copy()
                injected_params[param] = [value + payload for value in original_values]

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
                                break
                        else:
                            continue
                        break
                except requests.exceptions.RequestException as e:
                    logging.error(f"Error occurred while requesting {injected_url}: {e}")
                    continue

    return vulnerabilities
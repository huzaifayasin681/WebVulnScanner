# scanner/utils.py

from urllib.parse import urlparse

def is_valid_url(url):
    """
    Validates the URL by parsing its components.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        # Check for scheme and netloc
        return all([result.scheme in ("http", "https"), result.netloc])
    except:
        return False

def format_results(scan_results):
    """
    Formats the scan results into a human-readable plain text report.

    Args:
        scan_results (dict): The scan results dictionary.

    Returns:
        str: Formatted plain text report.
    """
    lines = []
    lines.append("Vulnerability Scan Report")
    lines.append("=========================\n")
    lines.append(f"Target URL      : {scan_results['target_url']}")
    lines.append(f"Scan Type       : {scan_results['scan_type'].upper()}")
    lines.append(f"Scan Depth      : {scan_results['depth']}\n")

    for vuln_type, results in scan_results['results'].items():
        lines.append(f"{vuln_type.upper()} Results:")
        if not results:
            lines.append("  No vulnerabilities found.\n")
            continue
        for idx, vuln in enumerate(results, 1):
            if vuln_type == "sqli":
                if "form_action" in vuln:
                    lines.append(f"  {idx}. Form Action: {vuln['form_action']}")
                    lines.append(f"     Method: {vuln['method']}")
                    lines.append(f"     Input Field: {vuln['input_field']}")
                else:
                    lines.append(f"  {idx}. Parameter: {vuln['parameter']}")
                lines.append(f"     Payload: {vuln['payload']}")
                lines.append(f"     Database: {vuln['db']}")
                lines.append(f"     Error: {vuln['error']}")
                lines.append(f"     URL: {vuln['url']}\n")
        lines.append("")  # Add empty line for spacing

    return "\n".join(lines)

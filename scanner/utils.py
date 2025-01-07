# scanner/utils.py

import re

def is_valid_url(url):
    # Simple regex for URL validation
    regex = re.compile(
        r'^(?:http|https)://'  # http:// or https://
        r'(?:\S+(?::\S*)?@)?'  # optional user:pass@
        r'(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+'  # domain
        r'[A-Za-z]{2,6}'  # TLD
        r'(?::\d{2,5})?'  # optional port
        r'(?:/\S*)?$'  # optional path
    )
    return re.match(regex, url) is not None

def format_results(scan_results):
    lines = []
    lines.append(f"Vulnerability Scan Report")
    lines.append(f"=========================\n")
    lines.append(f"Target URL      : {scan_results['target_url']}")
    lines.append(f"Scan Type       : {scan_results['scan_type'].upper()}")
    lines.append(f"Scan Depth      : {scan_results['depth']}\n")

    for vuln_type, results in scan_results['results'].items():
        lines.append(f"{vuln_type.upper()} Results:")
        if not results:
            lines.append("  No vulnerabilities found.\n")
            continue
        for idx, vuln in enumerate(results, 1):
            lines.append(f"  {idx}. {vuln}")
        lines.append("")  # Add empty line for spacing

    return "\n".join(lines)

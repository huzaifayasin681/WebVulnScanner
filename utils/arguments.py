import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Web Application Vulnerability Scanner (SQLi & XSS)'
    )
    parser.add_argument('--url', '-u', type=str, required=True, help='Target URL of the web application to scan.')
    parser.add_argument('--scan', '-s', type=str, choices=['sqli', 'xss', 'sqlxss'], required=True,
                        help='Type of vulnerability to scan: sqli (SQL Injection), xss (Cross-Site Scripting), or sqlxss (both).')
    parser.add_argument('--depth', '-d', type=int, default=1, help='Depth of the scan. Default is 1.')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output.')
    parser.add_argument('--output', '-o', type=str, default='outputs/results',
                        help='Base file path to save the scan results. Default is outputs/results.')
    return parser.parse_args()

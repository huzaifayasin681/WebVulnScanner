# scripts/run_scanner.py

import argparse
import json
import sys
import os
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)
from scanner import sqli_scanner, xss_scanner, utils

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Web Application Vulnerability Scanner (SQLi & XSS)'
    )

    parser.add_argument(
        '--url', '-u',
        type=str,
        required=True,
        help='Target URL of the web application to scan.'
    )

    parser.add_argument(
        '--scan', '-s',
        type=str,
        choices=['sqli', 'xss', 'sqlxss'],
        required=True,
        help='Type of vulnerability to scan for: '
             'sqli (SQL Injection), xss (Cross-Site Scripting), or sqlxss (both).'
    )

    parser.add_argument(
        '--depth', '-d',
        type=int,
        default=1,
        help='Depth of the scan (number of levels to traverse). Default is 1.'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output.'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        default='outputs/results',
        help='Base file path to save the scan results (without extension). Default is outputs/results.'
    )

    return parser.parse_args()

def main():
    args = parse_arguments()

    target_url = args.url
    scan_type = args.scan
    depth = args.depth
    verbose = args.verbose
    output_base = args.output

    # Validate URL
    if not utils.is_valid_url(target_url):
        print("[ERROR] Invalid URL provided.")
        sys.exit(1)

    if verbose:
        print(f"[INFO] Starting vulnerability scan on: {target_url}")
        print(f"[INFO] Vulnerabilities to scan: {scan_type.upper()}")
        print(f"[INFO] Scan depth: {depth}")

    # Initialize results dictionary
    scan_results = {
        'target_url': target_url,
        'scan_type': scan_type,
        'depth': depth,
        'results': {}
    }

    # Perform Scans based on scan_type
    if scan_type in ['sqli', 'sqlxss']:
        if verbose:
            print("[INFO] Performing SQL Injection scan...")
        sqli_results = sqli_scanner.perform_sqli_scan(target_url, depth, verbose)
        scan_results['results']['sqli'] = sqli_results

    if scan_type in ['xss', 'sqlxss']:
        if verbose:
            print("[INFO] Performing XSS scan...")
        xss_results = xss_scanner.perform_xss_scan(target_url, depth, verbose)
        scan_results['results']['xss'] = xss_results

    if verbose:
        print("[INFO] Scan completed.")

    # Prepare output directory
    output_dir = os.path.dirname(output_base)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Save results to JSON
    json_output_path = f"{output_base}.json"
    try:
        with open(json_output_path, 'w') as json_file:
            json.dump(scan_results, json_file, indent=4)
        if verbose:
            print(f"[INFO] JSON results saved to {json_output_path}")
    except Exception as e:
        print(f"[ERROR] Failed to write JSON output: {e}")
        sys.exit(1)

    # Save results to plain text
    txt_output_path = f"{output_base}.txt"
    try:
        with open(txt_output_path, 'w') as txt_file:
            txt_file.write(utils.format_results(scan_results))
        if verbose:
            print(f"[INFO] Plain text results saved to {txt_output_path}")
    except Exception as e:
        print(f"[ERROR] Failed to write plain text output: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()

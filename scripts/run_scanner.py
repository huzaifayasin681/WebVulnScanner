import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.arguments import parse_arguments
from utils.file_io import save_results_to_json, save_results_to_text, ensure_output_dir
from utils.validator import is_valid_url
from scanner import xss_scanner
from scanner.sqli import scanner

def main():
    args = parse_arguments()
    target_url = args.url
    scan_type = args.scan
    depth = args.depth
    verbose = args.verbose
    output_base = args.output

    # Validate URL
    if not is_valid_url(target_url):
        print("[ERROR] Invalid URL provided.")
        sys.exit(1)

    if verbose:
        print(f"[INFO] Starting vulnerability scan on: {target_url}")
        print(f"[INFO] Vulnerabilities to scan: {scan_type.upper()}")
        print(f"[INFO] Scan depth: {depth}")

    # Initialize results
    scan_results = {'target_url': target_url, 'scan_type': scan_type, 'depth': depth, 'results': {}}

    # Perform Scans
    if scan_type in ['sqli', 'sqlxss']:
        if verbose:
            print("[INFO] Performing SQL Injection scan...")
        scan_results['results']['sqli'] = scanner.perform_sqli_scan(target_url, depth, verbose)

    if scan_type in ['xss', 'sqlxss']:
        if verbose:
            print("[INFO] Performing XSS scan...")
        scan_results['results']['xss'] = xss_scanner.perform_xss_scan(target_url, depth, verbose)

    if verbose:
        print("[INFO] Scan completed.")

    # Save results
    ensure_output_dir(output_base)
    save_results_to_json(scan_results, output_base, verbose)
    formatted_results = "Results summary here..."  # Replace with real formatting logic
    save_results_to_text(scan_results, output_base, formatted_results, verbose)

if __name__ == '__main__':
    main()

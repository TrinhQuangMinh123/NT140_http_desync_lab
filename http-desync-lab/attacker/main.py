"""
Main entry point for HTTP Desync Lab Tester Script.
Orchestrates the entire testing flow: read payload, send via TCP, analyze results, export report.
"""

import argparse
import sys
import os
import re
from typing import Dict, Any, Optional

from . import sender
from . import utils


def analyze_results(response_bytes: bytes, backend_stdout: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze test results to detect HTTP desync vulnerability.
    
    Args:
        response_bytes: Raw response bytes from proxy
        backend_stdout: Backend stdout (if available)
    
    Returns:
        Analysis dictionary with vulnerability status
    """
    # Parse response to count HTTP responses
    response_text = response_bytes.decode('utf-8', errors='replace')
    
    # Count HTTP responses in proxy response (count "HTTP/1.1" or "HTTP/1.0" lines)
    proxy_responses = len(re.findall(r'HTTP/\d\.\d \d{3}', response_text))
    
    # Proxy recognized 1 request (the POST to /path1)
    proxy_recognized = 1
    
    # Backend recognized requests - check if /path2 was accessed
    backend_recognized = 1  # Default: only /path1
    smuggled_path = None
    
    # Check if response contains evidence of /path2 being accessed
    if '/path2' in response_text or 'SMUGGLED' in response_text:
        backend_recognized = 2
        smuggled_path = "/path2"
    
    # Determine vulnerability status
    if backend_recognized > proxy_recognized:
        vulnerability_status = "CRITICAL - Smuggling Successful"
    else:
        vulnerability_status = "NOT_VULNERABLE"
    
    # Extract proxy status code
    status_match = re.search(r'HTTP/\d\.\d (\d{3})', response_text)
    proxy_status = int(status_match.group(1)) if status_match else -1
    
    return {
        "test_case": "Trailer Section Injection",
        "proxy": "ATS 9.2.0",
        "backend": "gevent 23.7.0",
        "results": {
            "proxy_status": proxy_status,
            "proxy_recognized_requests": proxy_recognized,
            "backend_recognized_requests": backend_recognized,
            "smuggled_path_accessed": smuggled_path,
            "vulnerability_status": vulnerability_status
        }
    }


def collect_backend_stdout(pair_name: str) -> str:
    """
    Collect backend stdout from Docker container.
    
    Args:
        pair_name: Name of the pair (e.g., "ats_gevent")
    
    Returns:
        Backend stdout text
    """
    try:
        import subprocess
        result = subprocess.run(
            ['docker', 'compose', 'logs', 'backend'],
            cwd=f'pairs/{pair_name}',
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout
    except Exception as e:
        return f"[Failed to collect backend stdout: {e}]"


def main():
    """Main entry point for tester script."""
    parser = argparse.ArgumentParser(
        description='HTTP Desync Lab Tester Script'
    )
    parser.add_argument(
        '--target',
        required=True,
        help='Target pair name (e.g., ats_gevent)'
    )
    parser.add_argument(
        '--host',
        default='localhost',
        help='Proxy host (default: localhost)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=9080,
        help='Proxy port (default: 9080)'
    )
    
    args = parser.parse_args()
    
    pair_name = args.target
    host = args.host
    port = args.port
    
    # Determine paths
    output_dir = f'output/{pair_name}'
    payload_path = 'tester/payloads/trailer_smuggle.txt'
    test_case_name = "Trailer Section Injection"
    
    try:
        # Step 1: Read payload
        print(f"[*] Reading payload from {payload_path}")
        payload_bytes = utils.read_payload(payload_path)
        
        # Step 2: Write log separator
        print(f"[*] Writing log separator")
        utils.write_log_separator(output_dir, test_case_name)
        
        # Step 3: Log sent bytes
        print(f"[*] Logging sent bytes")
        utils.log_sent(output_dir, payload_bytes)
        
        # Step 4: Send via raw TCP socket
        print(f"[*] Sending payload to {host}:{port}")
        result = sender.send_raw(host, port, payload_bytes)
        
        if result.error is not None:
            print(f"[!] Error: {result.error}", file=sys.stderr)
            utils.log_error(output_dir, result.error)
            sys.exit(1)
        
        # Step 5: Log received bytes
        print(f"[*] Logging received bytes")
        utils.log_received(output_dir, result.response_bytes)
        
        # Step 6: Collect backend stdout
        print(f"[*] Collecting backend stdout")
        backend_stdout = collect_backend_stdout(pair_name)
        utils.log_backend_stdout(output_dir, backend_stdout)
        
        # Step 7: Analyze results
        print(f"[*] Analyzing results")
        analysis = analyze_results(result.response_bytes, backend_stdout)
        
        # Step 8: Write report
        print(f"[*] Writing report to {output_dir}/report.json")
        utils.write_report(output_dir, analysis)
        
        # Print summary
        print(f"\n[+] Test completed successfully")
        print(f"[+] Vulnerability Status: {analysis['results']['vulnerability_status']}")
        print(f"[+] Proxy recognized: {analysis['results']['proxy_recognized_requests']} request(s)")
        print(f"[+] Backend recognized: {analysis['results']['backend_recognized_requests']} request(s)")
        
        if analysis['results']['smuggled_path_accessed']:
            print(f"[+] Smuggled path accessed: {analysis['results']['smuggled_path_accessed']}")
        
    except FileNotFoundError as e:
        print(f"[!] File not found: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        utils.log_error(output_dir, str(e))
        sys.exit(1)


if __name__ == '__main__':
    main()

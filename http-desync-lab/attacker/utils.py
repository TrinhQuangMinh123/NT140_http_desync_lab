"""
Utility functions for HTTP Desync Lab Tester Script.
Handles payload reading, logging, and report generation.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any


def read_payload(path: str) -> bytes:
    """
    Read payload file and return raw bytes.
    
    Args:
        path: Path to payload file
    
    Returns:
        Raw bytes of payload with proper CRLF line endings
    
    Raises:
        FileNotFoundError: If payload file doesn't exist
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Payload file not found: {path}")
    
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Convert LF to CRLF for proper HTTP format
    # Replace any existing CRLF with LF first, then convert all LF to CRLF
    content = content.replace('\r\n', '\n').replace('\n', '\r\n')
    
    return content.encode('utf-8')


def write_log_separator(output_dir: str, test_case_name: str) -> None:
    """
    Write separator line with timestamp to log file.
    
    Args:
        output_dir: Directory for output files
        test_case_name: Name of the test case
    """
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, 'raw_traffic.log')
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    separator = f"\n{'=' * 60}\n"
    separator += f"[{timestamp}] TEST CASE: {test_case_name}\n"
    separator += f"{'=' * 60}\n"
    
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(separator)


def log_sent(output_dir: str, payload_bytes: bytes) -> None:
    """
    Log sent bytes to raw_traffic.log.
    
    Args:
        output_dir: Directory for output files
        payload_bytes: Bytes that were sent
    """
    log_path = os.path.join(output_dir, 'raw_traffic.log')
    
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write("[SENT BYTES]\n")
        f.write(payload_bytes.decode('utf-8', errors='replace'))
        f.write("\n\n")


def log_received(output_dir: str, response_bytes: bytes) -> None:
    """
    Log received bytes to raw_traffic.log.
    
    Args:
        output_dir: Directory for output files
        response_bytes: Bytes that were received
    """
    log_path = os.path.join(output_dir, 'raw_traffic.log')
    
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write("[RECEIVED BYTES FROM PROXY]\n")
        f.write(response_bytes.decode('utf-8', errors='replace'))
        f.write("\n\n")


def log_backend_stdout(output_dir: str, text: str) -> None:
    """
    Log backend stdout to raw_traffic.log.
    
    Args:
        output_dir: Directory for output files
        text: Backend stdout text
    """
    log_path = os.path.join(output_dir, 'raw_traffic.log')
    
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write("[BACKEND STDOUT]\n")
        f.write(text)
        f.write("\n\n")


def log_error(output_dir: str, error: str) -> None:
    """
    Log error message to raw_traffic.log.
    
    Args:
        output_dir: Directory for output files
        error: Error message
    """
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, 'raw_traffic.log')
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(f"[ERROR - {timestamp}]\n")
        f.write(error)
        f.write("\n\n")


def write_report(output_dir: str, analysis: Dict[str, Any]) -> None:
    """
    Write analysis report to report.json.
    
    Args:
        output_dir: Directory for output files
        analysis: Analysis dictionary containing test results
    """
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, 'report.json')
    
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)
        f.write('\n')

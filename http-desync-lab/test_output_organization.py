#!/usr/bin/env python3
"""
Test output directory organization by pair.
Verifies that output files are created in the correct locations.
"""

import sys
import os
import json
import tempfile
import shutil

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from attacker import utils


def test_output_directory_creation():
    """Test that output directory is created automatically."""
    # Use a temporary directory for testing
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = os.path.join(tmpdir, 'output', 'ats_gevent')
        
        # Verify directory doesn't exist yet
        assert not os.path.exists(output_dir), \
            "Output directory should not exist before test"
        
        # Call write_log_separator which should create the directory
        utils.write_log_separator(output_dir, "Test Case")
        
        # Verify directory was created
        assert os.path.exists(output_dir), \
            "Output directory should be created automatically"
        
        print(f"✓ Output directory created: {output_dir}")


def test_raw_traffic_log_location():
    """Test that raw_traffic.log is written to correct location."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = os.path.join(tmpdir, 'output', 'ats_gevent')
        
        # Write log separator
        utils.write_log_separator(output_dir, "Test Case")
        
        # Write sent bytes
        test_payload = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        utils.log_sent(output_dir, test_payload)
        
        # Write received bytes
        test_response = b"HTTP/1.1 200 OK\r\n\r\n"
        utils.log_received(output_dir, test_response)
        
        # Write backend stdout
        utils.log_backend_stdout(output_dir, "Backend log output")
        
        # Verify raw_traffic.log exists
        log_path = os.path.join(output_dir, 'raw_traffic.log')
        assert os.path.exists(log_path), \
            f"raw_traffic.log should exist at {log_path}"
        
        # Verify content
        with open(log_path, 'r') as f:
            content = f.read()
        
        assert "TEST CASE: Test Case" in content, \
            "Log should contain test case name"
        assert "[SENT BYTES]" in content, \
            "Log should contain sent bytes section"
        assert "[RECEIVED BYTES FROM PROXY]" in content, \
            "Log should contain received bytes section"
        assert "[BACKEND STDOUT]" in content, \
            "Log should contain backend stdout section"
        
        print(f"✓ raw_traffic.log written to correct location: {log_path}")
        print(f"✓ raw_traffic.log contains all required sections")


def test_report_json_location():
    """Test that report.json is written to correct location."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = os.path.join(tmpdir, 'output', 'ats_gevent')
        
        # Create test analysis
        analysis = {
            "test_case": "Test Case",
            "proxy": "Test Proxy",
            "backend": "Test Backend",
            "results": {
                "proxy_status": 200,
                "proxy_recognized_requests": 1,
                "backend_recognized_requests": 2,
                "smuggled_path_accessed": "/path2",
                "vulnerability_status": "CRITICAL - Smuggling Successful"
            }
        }
        
        # Write report
        utils.write_report(output_dir, analysis)
        
        # Verify report.json exists
        report_path = os.path.join(output_dir, 'report.json')
        assert os.path.exists(report_path), \
            f"report.json should exist at {report_path}"
        
        # Verify content
        with open(report_path, 'r') as f:
            loaded_analysis = json.load(f)
        
        assert loaded_analysis == analysis, \
            "Loaded analysis should match original"
        
        print(f"✓ report.json written to correct location: {report_path}")
        print(f"✓ report.json contains correct data")


def test_multiple_pairs_isolation():
    """Test that output from different pairs is isolated."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create output for ats_gevent
        ats_output_dir = os.path.join(tmpdir, 'output', 'ats_gevent')
        utils.write_log_separator(ats_output_dir, "ATS Test")
        utils.log_sent(ats_output_dir, b"ATS payload")
        
        # Create output for nginx_gunicorn
        nginx_output_dir = os.path.join(tmpdir, 'output', 'nginx_gunicorn')
        utils.write_log_separator(nginx_output_dir, "Nginx Test")
        utils.log_sent(nginx_output_dir, b"Nginx payload")
        
        # Verify both directories exist
        assert os.path.exists(ats_output_dir), \
            "ats_gevent output directory should exist"
        assert os.path.exists(nginx_output_dir), \
            "nginx_gunicorn output directory should exist"
        
        # Verify logs are separate
        ats_log = os.path.join(ats_output_dir, 'raw_traffic.log')
        nginx_log = os.path.join(nginx_output_dir, 'raw_traffic.log')
        
        with open(ats_log, 'r') as f:
            ats_content = f.read()
        with open(nginx_log, 'r') as f:
            nginx_content = f.read()
        
        assert "ATS Test" in ats_content, \
            "ATS log should contain ATS test case"
        assert "ATS payload" in ats_content, \
            "ATS log should contain ATS payload"
        assert "Nginx" not in ats_content, \
            "ATS log should not contain Nginx content"
        
        assert "Nginx Test" in nginx_content, \
            "Nginx log should contain Nginx test case"
        assert "Nginx payload" in nginx_content, \
            "Nginx log should contain Nginx payload"
        assert "ATS" not in nginx_content, \
            "Nginx log should not contain ATS content"
        
        print(f"✓ Output from different pairs is properly isolated")


def test_error_logging():
    """Test that errors are logged correctly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = os.path.join(tmpdir, 'output', 'ats_gevent')
        
        # Log an error
        error_message = "Connection refused"
        utils.log_error(output_dir, error_message)
        
        # Verify log exists
        log_path = os.path.join(output_dir, 'raw_traffic.log')
        assert os.path.exists(log_path), \
            "raw_traffic.log should exist after error logging"
        
        # Verify error content
        with open(log_path, 'r') as f:
            content = f.read()
        
        assert "[ERROR" in content, \
            "Log should contain error marker"
        assert error_message in content, \
            "Log should contain error message"
        
        print(f"✓ Errors are logged correctly")


def main():
    """Run all output organization tests."""
    print("=" * 70)
    print("Output Organization Tests")
    print("=" * 70)
    
    try:
        test_output_directory_creation()
        test_raw_traffic_log_location()
        test_report_json_location()
        test_multiple_pairs_isolation()
        test_error_logging()
        
        print("\n" + "=" * 70)
        print("✓ ALL OUTPUT ORGANIZATION TESTS PASSED!")
        print("=" * 70)
        print("\nVerified:")
        print("  - Output directories are created automatically")
        print("  - raw_traffic.log is written to output/{pair_name}/")
        print("  - report.json is written to output/{pair_name}/")
        print("  - Output from different pairs is isolated")
        print("  - Errors are logged correctly")
        
        return 0
    
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

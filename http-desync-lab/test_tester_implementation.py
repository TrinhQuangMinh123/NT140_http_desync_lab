#!/usr/bin/env python3
"""
Integration test for Tester Script implementation.
Verifies all components work together correctly.
"""

import sys
import os
import json

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from attacker import utils, sender
from attacker.main import analyze_results


def test_payload_reading():
    """Test payload file reading and CRLF conversion."""
    print("Testing payload reading...")
    payload_bytes = utils.read_payload('http-desync-lab/tester/payloads/trailer_smuggle.txt')
    
    # Verify payload structure
    payload_str = payload_bytes.decode('utf-8')
    assert 'POST /path1 HTTP/1.1' in payload_str, "Missing POST request"
    assert 'Transfer-Encoding: chunked' in payload_str, "Missing chunked encoding"
    assert 'GET /path2 HTTP/1.1' in payload_str, "Missing smuggled request"
    assert b'\r\n' in payload_bytes, "Missing CRLF line endings"
    assert '0\r\n' in payload_str, "Missing final chunk marker"
    
    print(f"  ✓ Payload loaded: {len(payload_bytes)} bytes")
    print(f"  ✓ Contains proper CRLF line endings")
    print(f"  ✓ Contains chunked encoding structure")
    print(f"  ✓ Contains smuggled request")
    return payload_bytes


def test_sender_module():
    """Test sender module error handling."""
    print("\nTesting sender module...")
    
    # Test invalid port
    result = sender.send_raw('localhost', 99999, b'test')
    assert result.error is not None, "Should detect invalid port"
    print(f"  ✓ Invalid port detection: {result.error}")
    
    # Test empty payload
    result = sender.send_raw('localhost', 9080, b'')
    assert result.error is not None, "Should detect empty payload"
    print(f"  ✓ Empty payload detection: {result.error}")


def test_logging_functions():
    """Test all logging functions."""
    print("\nTesting logging functions...")
    test_dir = 'output/integration_test'
    
    # Clean up if exists
    if os.path.exists(test_dir):
        import shutil
        shutil.rmtree(test_dir)
    
    # Test all logging functions
    utils.write_log_separator(test_dir, 'Integration Test')
    utils.log_sent(test_dir, b'test payload')
    utils.log_received(test_dir, b'test response')
    utils.log_backend_stdout(test_dir, 'backend output')
    utils.log_error(test_dir, 'test error')
    
    # Verify log file exists and has content
    log_path = os.path.join(test_dir, 'raw_traffic.log')
    assert os.path.exists(log_path), "Log file not created"
    
    with open(log_path, 'r') as f:
        log_content = f.read()
        assert 'Integration Test' in log_content, "Missing test case name"
        assert '[SENT BYTES]' in log_content, "Missing sent bytes section"
        assert '[RECEIVED BYTES FROM PROXY]' in log_content, "Missing received bytes section"
        assert '[BACKEND STDOUT]' in log_content, "Missing backend stdout section"
        assert '[ERROR' in log_content, "Missing error section"
    
    print(f"  ✓ Log separator written")
    print(f"  ✓ Sent bytes logged")
    print(f"  ✓ Received bytes logged")
    print(f"  ✓ Backend stdout logged")
    print(f"  ✓ Error logged")
    
    # Clean up
    import shutil
    shutil.rmtree(test_dir)


def test_report_generation():
    """Test report generation and JSON validity."""
    print("\nTesting report generation...")
    test_dir = 'output/integration_test'
    
    test_analysis = {
        'test_case': 'Integration Test',
        'proxy': 'ATS 9.2.0',
        'backend': 'gevent 23.7.0',
        'results': {
            'proxy_status': 200,
            'proxy_recognized_requests': 1,
            'backend_recognized_requests': 2,
            'smuggled_path_accessed': '/path2',
            'vulnerability_status': 'CRITICAL - Smuggling Successful'
        }
    }
    
    utils.write_report(test_dir, test_analysis)
    
    # Verify report exists and is valid JSON
    report_path = os.path.join(test_dir, 'report.json')
    assert os.path.exists(report_path), "Report file not created"
    
    with open(report_path, 'r') as f:
        loaded = json.load(f)
        assert loaded == test_analysis, "Report content mismatch"
    
    # Test round-trip (P1 property)
    serialized = json.dumps(loaded)
    reloaded = json.loads(serialized)
    assert reloaded == test_analysis, "Round-trip failed"
    
    print(f"  ✓ Report generated successfully")
    print(f"  ✓ Report is valid JSON")
    print(f"  ✓ Round-trip property verified (P1)")
    
    # Clean up
    import shutil
    shutil.rmtree(test_dir)


def test_analyze_results():
    """Test result analysis logic."""
    print("\nTesting result analysis...")
    
    # Test successful smuggling
    response1 = b'HTTP/1.1 200 OK\r\n\r\nOK - path1HTTP/1.1 200 OK\r\n\r\nOK - path2 (SMUGGLED)'
    result1 = analyze_results(response1)
    assert result1['results']['backend_recognized_requests'] == 2, "Should detect 2 requests"
    assert result1['results']['vulnerability_status'] == 'CRITICAL - Smuggling Successful', "Should detect vulnerability"
    assert result1['results']['smuggled_path_accessed'] == '/path2', "Should detect smuggled path"
    print(f"  ✓ Successful smuggling detected")
    
    # Test no smuggling
    response2 = b'HTTP/1.1 200 OK\r\n\r\nOK - path1'
    result2 = analyze_results(response2)
    assert result2['results']['backend_recognized_requests'] == 1, "Should detect 1 request"
    assert result2['results']['vulnerability_status'] == 'NOT_VULNERABLE', "Should not detect vulnerability"
    assert result2['results']['smuggled_path_accessed'] is None, "Should not detect smuggled path"
    print(f"  ✓ No smuggling correctly identified")
    
    # Test desync detection correctness (P2 property)
    print(f"  ✓ Desync detection logic verified (P2)")


def main():
    """Run all integration tests."""
    print("=" * 60)
    print("HTTP Desync Lab - Tester Script Integration Test")
    print("=" * 60)
    
    try:
        payload_bytes = test_payload_reading()
        test_sender_module()
        test_logging_functions()
        test_report_generation()
        test_analyze_results()
        
        print("\n" + "=" * 60)
        print("✓ ALL INTEGRATION TESTS PASSED!")
        print("=" * 60)
        print("\nTester Script is ready for use:")
        print("  python3 -m attacker.main --target ats_gevent")
        print("  python3 tester/run_test.py --target ats_gevent")
        
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

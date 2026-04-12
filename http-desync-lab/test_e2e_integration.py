#!/usr/bin/env python3
"""
End-to-end integration test for HTTP Desync Lab.
Tests the complete system: Docker containers, Tester Script, and vulnerability detection.

Task 7: Kiểm tra tích hợp end-to-end
  7.1: Xác minh docker compose up khởi động thành công trong 60 giây
  7.2: Chạy attacker và xác minh report.json với vulnerability_status = "CRITICAL - Smuggling Successful"
  7.3: Xác minh raw_traffic.log chứa đầy đủ thông tin
  7.4: Xác minh Proxy trả về 403 khi gửi request trực tiếp tới /path2
"""

import subprocess
import time
import os
import sys
import json
import socket

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))


def run_command(cmd, cwd=None, timeout=60, check=True):
    """Run a shell command and return result."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check
        )
        return result
    except subprocess.TimeoutExpired:
        raise Exception(f"Command timed out after {timeout}s: {' '.join(cmd)}")
    except subprocess.CalledProcessError as e:
        raise Exception(f"Command failed: {' '.join(cmd)}\nStderr: {e.stderr}")


def test_7_1_docker_compose_startup():
    """
    Task 7.1: Xác minh docker compose up khởi động thành công
    cả Proxy (cổng 9080) và Backend (nội bộ cổng 5000) trong vòng 60 giây
    """
    print("\n" + "=" * 70)
    print("Task 7.1: Testing Docker Compose Startup")
    print("=" * 70)
    
    pair_dir = "pairs/ats_gevent"
    
    # Stop any existing containers
    print("[*] Stopping any existing containers...")
    run_command(
        ["docker", "compose", "down"],
        cwd=pair_dir,
        check=False
    )
    time.sleep(2)
    
    # Start containers
    print("[*] Starting Docker containers...")
    start_time = time.time()
    
    run_command(
        ["docker", "compose", "up", "-d", "--build"],
        cwd=pair_dir,
        timeout=120
    )
    
    # Wait for containers to be healthy
    print("[*] Waiting for containers to be ready...")
    max_wait = 60
    elapsed = 0
    proxy_ready = False
    backend_ready = False
    
    while elapsed < max_wait:
        # Check if proxy port 9080 is accessible
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', 9080))
            sock.close()
            if result == 0:
                proxy_ready = True
        except:
            pass
        
        # Check if backend container is running
        result = run_command(
            ["docker", "compose", "ps", "-q", "backend"],
            cwd=pair_dir,
            check=False
        )
        if result.stdout.strip():
            backend_ready = True
        
        if proxy_ready and backend_ready:
            break
        
        time.sleep(2)
        elapsed = time.time() - start_time
    
    total_time = time.time() - start_time
    
    # Verify both services are running
    assert proxy_ready, "Proxy (port 9080) not accessible after 60 seconds"
    assert backend_ready, "Backend container not running after 60 seconds"
    assert total_time < 60, f"Startup took {total_time:.1f}s (should be < 60s)"
    
    print(f"  ✓ Proxy accessible on port 9080")
    print(f"  ✓ Backend container running (internal port 5000)")
    print(f"  ✓ Startup completed in {total_time:.1f} seconds (< 60s)")
    
    # Verify containers are actually running
    result = run_command(
        ["docker", "compose", "ps"],
        cwd=pair_dir
    )
    print(f"\n[*] Container status:")
    print(result.stdout)
    
    return True


def test_7_2_attacker_script_and_report():
    """
    Task 7.2: Chạy python attacker/main.py --target ats_gevent
    và xác minh output/ats_gevent/report.json được tạo
    với vulnerability_status = "CRITICAL - Smuggling Successful"
    """
    print("\n" + "=" * 70)
    print("Task 7.2: Testing Attacker Script and Report Generation")
    print("=" * 70)
    
    # Clean output directory
    output_dir = "output/ats_gevent"
    report_path = os.path.join(output_dir, "report.json")
    
    if os.path.exists(report_path):
        os.remove(report_path)
        print(f"[*] Cleaned existing report: {report_path}")
    
    # Run attacker script
    print("[*] Running attacker script...")
    result = run_command(
        [sys.executable, "-m", "attacker.main", "--target", "ats_gevent"],
        timeout=30
    )
    
    print(result.stdout)
    
    # Verify report.json exists
    assert os.path.exists(report_path), f"Report file not created: {report_path}"
    print(f"  ✓ Report file created: {report_path}")
    
    # Load and verify report content
    with open(report_path, 'r') as f:
        report = json.load(f)
    
    print(f"\n[*] Report content:")
    print(json.dumps(report, indent=2))
    
    # Verify required fields
    assert "test_case" in report, "Missing 'test_case' field"
    assert "proxy" in report, "Missing 'proxy' field"
    assert "backend" in report, "Missing 'backend' field"
    assert "results" in report, "Missing 'results' field"
    
    results = report["results"]
    assert "proxy_status" in results, "Missing 'proxy_status' field"
    assert "proxy_recognized_requests" in results, "Missing 'proxy_recognized_requests' field"
    assert "backend_recognized_requests" in results, "Missing 'backend_recognized_requests' field"
    assert "smuggled_path_accessed" in results, "Missing 'smuggled_path_accessed' field"
    assert "vulnerability_status" in results, "Missing 'vulnerability_status' field"
    
    # Verify vulnerability detection
    assert results["vulnerability_status"] == "CRITICAL - Smuggling Successful", \
        f"Expected 'CRITICAL - Smuggling Successful', got '{results['vulnerability_status']}'"
    
    assert results["proxy_recognized_requests"] == 1, \
        f"Expected proxy to recognize 1 request, got {results['proxy_recognized_requests']}"
    
    assert results["backend_recognized_requests"] == 2, \
        f"Expected backend to recognize 2 requests, got {results['backend_recognized_requests']}"
    
    assert results["smuggled_path_accessed"] == "/path2", \
        f"Expected smuggled path '/path2', got '{results['smuggled_path_accessed']}'"
    
    print(f"\n  ✓ Report contains all required fields")
    print(f"  ✓ vulnerability_status = 'CRITICAL - Smuggling Successful'")
    print(f"  ✓ proxy_recognized_requests = 1")
    print(f"  ✓ backend_recognized_requests = 2")
    print(f"  ✓ smuggled_path_accessed = '/path2'")
    
    return True


def test_7_3_raw_traffic_log():
    """
    Task 7.3: Xác minh output/ats_gevent/raw_traffic.log chứa
    dòng phân cách timestamp, bytes đã gửi, bytes nhận được từ Proxy,
    và stdout của Backend
    """
    print("\n" + "=" * 70)
    print("Task 7.3: Testing Raw Traffic Log")
    print("=" * 70)
    
    log_path = "output/ats_gevent/raw_traffic.log"
    
    # Verify log file exists
    assert os.path.exists(log_path), f"Log file not found: {log_path}"
    print(f"  ✓ Log file exists: {log_path}")
    
    # Read log content
    with open(log_path, 'r') as f:
        log_content = f.read()
    
    # Verify required sections
    assert "========================================" in log_content, \
        "Missing separator line"
    print(f"  ✓ Contains separator line")
    
    # Check for timestamp (format: [YYYY-MM-DD HH:MM:SS])
    import re
    timestamp_pattern = r'\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]'
    assert re.search(timestamp_pattern, log_content), \
        "Missing timestamp in format [YYYY-MM-DD HH:MM:SS]"
    print(f"  ✓ Contains timestamp")
    
    assert "TEST CASE:" in log_content or "Trailer Section Injection" in log_content, \
        "Missing test case name"
    print(f"  ✓ Contains test case name")
    
    assert "[SENT BYTES]" in log_content, \
        "Missing [SENT BYTES] section"
    print(f"  ✓ Contains [SENT BYTES] section")
    
    assert "[RECEIVED BYTES FROM PROXY]" in log_content, \
        "Missing [RECEIVED BYTES FROM PROXY] section"
    print(f"  ✓ Contains [RECEIVED BYTES FROM PROXY] section")
    
    assert "[BACKEND STDOUT]" in log_content, \
        "Missing [BACKEND STDOUT] section"
    print(f"  ✓ Contains [BACKEND STDOUT] section")
    
    # Verify sent bytes contain the payload structure
    assert "POST /path1 HTTP/1.1" in log_content, \
        "Sent bytes missing POST request"
    assert "Transfer-Encoding: chunked" in log_content, \
        "Sent bytes missing chunked encoding"
    assert "GET /path2 HTTP/1.1" in log_content, \
        "Sent bytes missing smuggled request"
    print(f"  ✓ Sent bytes contain complete payload structure")
    
    # Verify received bytes contain response
    assert "HTTP/1.1" in log_content or "HTTP/1.0" in log_content, \
        "Received bytes missing HTTP response"
    print(f"  ✓ Received bytes contain HTTP response")
    
    print(f"\n[*] Log file size: {len(log_content)} bytes")
    
    return True


def test_7_4_proxy_access_control():
    """
    Task 7.4: Xác minh Proxy trả về 403 khi gửi request trực tiếp
    tới /path2 (không qua smuggling)
    """
    print("\n" + "=" * 70)
    print("Task 7.4: Testing Proxy Access Control")
    print("=" * 70)
    
    # Test direct access to /path2 (should be blocked)
    print("[*] Testing direct access to /path2...")
    
    request = b"GET /path2 HTTP/1.1\r\nHost: localhost\r\n\r\n"
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', 9080))
        sock.sendall(request)
        
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            # Break if we have the status line
            if b"\r\n\r\n" in response:
                break
        
        sock.close()
        
        response_text = response.decode('utf-8', errors='replace')
        print(f"\n[*] Response received:")
        print(response_text[:200])  # Print first 200 chars
        
        # Check for 403 Forbidden
        assert "403" in response_text or "Forbidden" in response_text, \
            f"Expected 403 Forbidden, got: {response_text[:100]}"
        
        print(f"\n  ✓ Proxy correctly returns 403 Forbidden for direct /path2 access")
        
    except Exception as e:
        raise Exception(f"Failed to test proxy access control: {e}")
    
    # Test access to /path1 (should be allowed)
    print("\n[*] Testing direct access to /path1 (should be allowed)...")
    
    request = b"GET /path1 HTTP/1.1\r\nHost: localhost\r\n\r\n"
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', 9080))
        sock.sendall(request)
        
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response:
                break
        
        sock.close()
        
        response_text = response.decode('utf-8', errors='replace')
        print(f"\n[*] Response received:")
        print(response_text[:200])
        
        # Check for 200 OK (not 403)
        assert "200" in response_text or "OK" in response_text, \
            f"Expected 200 OK for /path1, got: {response_text[:100]}"
        assert "403" not in response_text, \
            f"Unexpected 403 for /path1: {response_text[:100]}"
        
        print(f"\n  ✓ Proxy correctly allows access to /path1")
        
    except Exception as e:
        raise Exception(f"Failed to test /path1 access: {e}")
    
    return True


def cleanup():
    """Clean up Docker containers."""
    print("\n" + "=" * 70)
    print("Cleanup")
    print("=" * 70)
    
    pair_dir = "pairs/ats_gevent"
    print("[*] Stopping Docker containers...")
    
    result = run_command(
        ["docker", "compose", "down"],
        cwd=pair_dir,
        check=False
    )
    
    print(f"  ✓ Containers stopped")


def check_docker_available():
    """Check if Docker is available."""
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            timeout=5,
            check=False
        )
        return result.returncode == 0
    except:
        return False


def main():
    """Run all end-to-end integration tests."""
    print("=" * 70)
    print("HTTP Desync Lab - End-to-End Integration Test")
    print("Task 7: Kiểm tra tích hợp end-to-end")
    print("=" * 70)
    
    # Check Docker availability
    docker_available = check_docker_available()
    if not docker_available:
        print("\n[!] WARNING: Docker is not available")
        print("[!] This test requires Docker to run the full integration test")
        print("[!] Please install Docker and Docker Compose, then run:")
        print("[!]   cd http-desync-lab/pairs/ats_gevent")
        print("[!]   docker compose up -d --build")
        print("[!]   cd ../..")
        print("[!]   python3 test_e2e_integration.py")
        print("\n[*] Test structure is ready, but cannot execute without Docker")
        return 1
    
    try:
        # Task 7.1: Docker compose startup
        test_7_1_docker_compose_startup()
        
        # Task 7.2: Attacker script and report
        test_7_2_attacker_script_and_report()
        
        # Task 7.3: Raw traffic log
        test_7_3_raw_traffic_log()
        
        # Task 7.4: Proxy access control
        test_7_4_proxy_access_control()
        
        print("\n" + "=" * 70)
        print("✓ ALL END-TO-END INTEGRATION TESTS PASSED!")
        print("=" * 70)
        print("\nTask 7 completed successfully:")
        print("  ✓ 7.1: Docker compose startup verified")
        print("  ✓ 7.2: Attacker script and report verified")
        print("  ✓ 7.3: Raw traffic log verified")
        print("  ✓ 7.4: Proxy access control verified")
        
        return 0
    
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        cleanup()


if __name__ == '__main__':
    sys.exit(main())

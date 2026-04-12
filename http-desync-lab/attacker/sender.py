"""
Raw TCP socket sender for HTTP Desync Lab.
Sends payload bytes over raw TCP connection without using high-level HTTP libraries.
"""

import socket
from dataclasses import dataclass
from typing import Optional


@dataclass
class SendResult:
    """Result of sending payload via TCP socket."""
    response_bytes: Optional[bytes] = None
    error: Optional[str] = None


def send_raw(host: str, port: int, payload_bytes: bytes) -> SendResult:
    """
    Send payload via raw TCP socket and return response.
    
    Args:
        host: Target host address
        port: Target port (1-65535)
        payload_bytes: Raw bytes to send
    
    Returns:
        SendResult containing response_bytes on success or error message on failure
    """
    if not payload_bytes:
        return SendResult(error="Payload is empty")
    
    if not (1 <= port <= 65535):
        return SendResult(error=f"Invalid port: {port}")
    
    sock = None
    try:
        # Create raw TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # 10 second timeout
        
        # Connect to target
        sock.connect((host, port))
        
        # Send all payload bytes
        sock.sendall(payload_bytes)
        
        # Receive response (read until connection closes or timeout)
        response_chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_chunks.append(chunk)
            except socket.timeout:
                break
        
        response_bytes = b''.join(response_chunks)
        return SendResult(response_bytes=response_bytes, error=None)
    
    except ConnectionRefusedError as e:
        return SendResult(error=f"Connection refused: {e}")
    except socket.timeout as e:
        return SendResult(error=f"Connection timeout: {e}")
    except OSError as e:
        return SendResult(error=f"Socket error: {e}")
    except Exception as e:
        return SendResult(error=f"Unexpected error: {e}")
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass

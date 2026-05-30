#!/usr/bin/env python3
"""
fake_upstream.py — Response-side Harness (paper §4.3.2 mode 2)
---------------------------------------------------------------
A minimal TCP server that plays the role of an upstream server to a
reverse proxy under test. The fuzzer queues a response payload, the
proxy contacts the upstream, and this server returns the queued bytes
verbatim — allowing us to exercise the proxy's RESPONSE parser with
malformed HTTP responses (TE.CL conflicts, trailer abuse, etc.).

Architecture:
    fuzzer ──GET /resp-test─▶ proxy ──forward──▶ fake_upstream (this)
                                                       │
    fuzzer ◀──response──────── proxy ◀──response──────┘

The fuzzer compares what arrived at the client vs the bytes we sent
upstream → response-side desync detection.

Usage:
    Programmatic (from runner):
        up = FakeUpstream(port=9501)
        up.serve_once(response_bytes, timeout=5)

    Standalone for debugging:
        python3 fake_upstream.py --port 9501 --payload some_file.txt
"""

import argparse
import logging
import os
import socket
import threading
import time

logger = logging.getLogger("FakeUpstream")


class FakeUpstream:
    """
    One-shot upstream server. Each call to serve_once() accepts a SINGLE
    incoming connection, swallows whatever it sends, and replies with the
    pre-queued response bytes. Closes the socket after.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 9501):
        self.host = host
        self.port = port
        self._last_request_bytes = b""
        self._lock = threading.Lock()

    def serve_once(self, response: bytes, timeout: float = 5.0) -> bytes:
        """
        Listen for one connection from the proxy. Read its request (so
        the proxy sees a clean RX), then send `response` verbatim. Return
        the raw bytes the proxy sent us (useful for debugging).
        """
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(1)
        srv.settimeout(timeout)
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            srv.close()
            return b""
        conn.settimeout(timeout)
        # Read upstream-bound request (headers at minimum).
        received = b""
        try:
            while b"\r\n\r\n" not in received and len(received) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                received += chunk
        except socket.timeout:
            pass
        with self._lock:
            self._last_request_bytes = received
        # Send the test-case response verbatim.
        try:
            conn.sendall(response)
        except Exception:
            pass
        # Half-close gracefully so proxy reads EOF.
        try:
            conn.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        # Drain anything the proxy might still send.
        try:
            while True:
                if not conn.recv(4096):
                    break
        except Exception:
            pass
        conn.close()
        srv.close()
        return received

    def last_request(self) -> bytes:
        with self._lock:
            return self._last_request_bytes


def serve_in_thread(upstream: FakeUpstream, response: bytes,
                    timeout: float = 5.0) -> threading.Thread:
    """Run serve_once in a background thread; returns the thread object."""
    t = threading.Thread(
        target=upstream.serve_once,
        args=(response, timeout),
        daemon=True,
    )
    t.start()
    # Give the listener a moment to bind before the caller initiates the
    # client request that the proxy will forward upstream.
    time.sleep(0.05)
    return t


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Fake upstream server for response-side fuzzing")
    p.add_argument("--port", type=int, default=9501)
    p.add_argument("--payload", required=True,
                   help="Path to file containing raw HTTP response bytes")
    p.add_argument("--timeout", type=float, default=5.0)
    args = p.parse_args()

    with open(args.payload, "rb") as f:
        body = f.read()
    upstream = FakeUpstream(port=args.port)
    print(f"[fake_upstream] Listening on 0.0.0.0:{args.port}, waiting one conn ...")
    req = upstream.serve_once(body, timeout=args.timeout)
    print(f"[fake_upstream] Proxy sent us {len(req)} bytes")
    print(req.decode("latin-1", errors="replace"))

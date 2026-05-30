#!/usr/bin/env python3
"""
wire_tap.py — Proxy→Backend wire-level observation (medium-tier internal state)
-------------------------------------------------------------------------------
Standalone TCP relay placed between the reverse proxy and the backend so the
fuzzer can record EXACTLY what the proxy forwarded — at the byte level,
before any backend HTTP parsing.

This gives us "wire-level ground truth" that paper §4.4.1 obtains by
inserting code into the parser. We can't easily instrument NGINX/HAProxy
binaries, but a transparent relay achieves comparable visibility:

    Client ──▶ Proxy ──▶ wire_tap.py ──▶ Backend
                              │
                              └──▶ /tmp/wire_tap.log (every byte, both directions)

Usage:
    # Terminal A:
    python3 04_fuzzer_engine/wire_tap.py \
        --listen 0.0.0.0:9100 --upstream 127.0.0.1:9001 \
        --log /tmp/wire_tap_nginx.log

    # Terminal B: enable tap in NGINX by switching proxy_pass to
    # host.docker.internal:9100 (see docker-compose.wiretap.yml override)
    docker compose -f 02_targets/nginx_gunicorn/docker-compose.yml \
                   -f 02_targets/nginx_gunicorn/docker-compose.wiretap.yml up -d

    # Terminal C: run fuzzer; afterwards inspect /tmp/wire_tap_nginx.log

Each log entry is JSON, one per line:
    {"ts": 1234.567, "conn": 42, "dir": "c2s|s2c", "len": N, "hex": "..."}
"""

import argparse
import json
import logging
import os
import socket
import sys
import threading
import time

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("wire_tap")


def _emit(log_file, conn_id, direction, data: bytes):
    """Write one JSON line per byte chunk relayed."""
    if not data:
        return
    entry = {
        "ts":  round(time.time(), 4),
        "conn": conn_id,
        "dir": direction,
        "len": len(data),
        "hex": data[:512].hex(),  # cap to 512 bytes/chunk to keep log readable
    }
    log_file.write(json.dumps(entry) + "\n")
    log_file.flush()


def _pipe(src, dst, conn_id, direction, log_file):
    """One-way pump: src → dst, logging every byte."""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            _emit(log_file, conn_id, direction, data)
            try:
                dst.sendall(data)
            except OSError:
                break
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _handle(client_sock: socket.socket, conn_id: int,
            upstream_host: str, upstream_port: int, log_file):
    """Spawned per inbound connection from the proxy."""
    try:
        backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend.settimeout(10)
        backend.connect((upstream_host, upstream_port))
        backend.settimeout(None)
    except OSError as e:
        log.warning(f"[wire_tap] backend connect failed: {e}")
        client_sock.close()
        return

    t_up = threading.Thread(
        target=_pipe, args=(client_sock, backend, conn_id, "c2s", log_file),
        daemon=True,
    )
    t_down = threading.Thread(
        target=_pipe, args=(backend, client_sock, conn_id, "s2c", log_file),
        daemon=True,
    )
    t_up.start()
    t_down.start()
    t_up.join()
    t_down.join()
    client_sock.close()
    backend.close()


def serve(listen_host, listen_port, upstream_host, upstream_port, log_path):
    log_file = open(log_path, "a", buffering=1)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_host, listen_port))
    srv.listen(128)
    log.info(f"[wire_tap] {listen_host}:{listen_port} → "
             f"{upstream_host}:{upstream_port}  log={log_path}")
    next_conn_id = 0
    try:
        while True:
            client, addr = srv.accept()
            conn_id = next_conn_id
            next_conn_id += 1
            t = threading.Thread(
                target=_handle,
                args=(client, conn_id, upstream_host, upstream_port, log_file),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        log.info("[wire_tap] shutting down")
    finally:
        srv.close()
        log_file.close()


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("--listen", default="0.0.0.0:9100",
                   help="Listen address (default 0.0.0.0:9100)")
    p.add_argument("--upstream", default="127.0.0.1:9001",
                   help="Upstream backend address (default 127.0.0.1:9001)")
    p.add_argument("--log", default="/tmp/wire_tap.log",
                   help="JSON-lines log path (default /tmp/wire_tap.log)")
    args = p.parse_args()

    lh, lp = args.listen.rsplit(":", 1)
    uh, up = args.upstream.rsplit(":", 1)
    serve(lh, int(lp), uh, int(up), args.log)


if __name__ == "__main__":
    main()

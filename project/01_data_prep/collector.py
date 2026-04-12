#!/usr/bin/env python3
"""
collector.py - Golden Seed Corpus Generator
--------------------------------------------
Generates a curated set of 12 high-coverage HTTP/1.1 seed files.
Each seed represents a unique syntactic or semantic edge-case of 
the HTTP protocol that commonly triggers parser discrepancies.
"""

import os

SEEDS_DIR = os.path.join(os.path.dirname(__file__), "seeds_db")


GOLDEN_SEEDS = {
    "seed_01_get_standard.txt": (
        b"GET / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    ),

    "seed_02_post_content_length.txt": (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 11\r\n"
        b"\r\n"
        b"hello=world"
    ),

    "seed_03_post_chunked.txt": (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"b\r\n"
        b"hello=world\r\n"
        b"0\r\n"
        b"\r\n"
    ),

    "seed_04_te_line_folding.txt": (
        # RFC7230 prohibits this. Many proxies ignore folding, some don't.
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 4\r\n"
        b"Transfer-Encoding:\r\n"
        b" chunked\r\n"
        b"\r\n"
        b"4\r\n"
        b"AAAA\r\n"
        b"0\r\n"
        b"\r\n"
    ),

    "seed_05_absolute_uri.txt": (
        # Proxy-style absolute URI: Nginx strips the host, backend may not.
        b"GET http://localhost/ HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    ),

    "seed_06_double_content_length.txt": (
        # RFC says: reject if multiple CL differ. 
        # Some proxies pick first, some pick last.
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 11\r\n"
        b"Content-Length: 5\r\n"
        b"\r\n"
        b"hello=world"
    ),

    "seed_07_cl_te_conflict.txt": (
        # Classic CL.TE: Proxy uses CL=6, Backend uses TE (chunked).
        # Backend reads chunk "0\r\n\r\n" then sees "X" as next request.
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 6\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n"
        b"\r\n"
        b"X"
    ),

    "seed_08_te_cl_conflict.txt": (
        # Classic TE.CL: Proxy uses TE. Backend uses CL=3.
        # Backend reads only 3 bytes ("5\r\n"), leaving remainder as next req.
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 3\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5\r\n"
        b"12345\r\n"
        b"0\r\n"
        b"\r\n"
    ),

    "seed_09_chunk_extension.txt": (
        # Chunk extensions are rarely used. Many parsers mishandle them.
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5;ext=evil\r\n"
        b"ABCDE\r\n"
        b"0\r\n"
        b"\r\n"
    ),

    "seed_10_trailer_headers.txt": (
        # Trailer headers come AFTER chunked body. Most backends ignore them.
        # Nginx may strip, Gunicorn may not — scope for size discrepancy.
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Trailer: X-Secret\r\n"
        b"\r\n"
        b"5\r\n"
        b"ABCDE\r\n"
        b"0\r\n"
        b"X-Secret: leaked\r\n"
        b"\r\n"
    ),

    "seed_11_pipelining.txt": (
        # Two requests back-to-back on the same TCP connection.
        # If backend processes both but proxy only forwards first response = desync.
        b"GET / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"\r\n"
        b"GET /second HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    ),

    "seed_12_padded_content_length.txt": (
        # Padded integer: "00011" is still 11.
        # Python Gunicorn accepts it; Nginx rejects with 400.
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 00011\r\n"
        b"\r\n"
        b"hello=world"
    ),
}


def generate():
    os.makedirs(SEEDS_DIR, exist_ok=True)

    # Remove old seeds to avoid stale data
    for f in os.listdir(SEEDS_DIR):
        if f.endswith(".txt"):
            os.remove(os.path.join(SEEDS_DIR, f))

    print("=" * 60)
    print("  HTTP Desync — Golden Seed Corpus Generator")
    print("=" * 60)

    for filename, payload in GOLDEN_SEEDS.items():
        path = os.path.join(SEEDS_DIR, filename)
        with open(path, "wb") as fh:
            fh.write(payload)

        first_line = payload.split(b"\r\n")[0].decode("latin-1")
        print(f"  [+] {filename:45s}  ({len(payload):4d} bytes)  [{first_line}]")

    print(f"\n  [✓] {len(GOLDEN_SEEDS)} Golden Seeds written to: {SEEDS_DIR}")


if __name__ == "__main__":
    generate()
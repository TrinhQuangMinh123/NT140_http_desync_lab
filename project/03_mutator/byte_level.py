#!/usr/bin/env python3
"""
byte_level.py - Byte-Level HTTP Mutator
-----------------------------------------
Replicates HDHunter's 4 byte-level mutators that operate directly on the
raw byte representation of a single HTTP message component:
  - ByteInsertMutator    : insert a random byte at a random offset
  - ByteRemoveMutator    : remove a byte at a random offset
  - ByteDuplicateMutator : duplicate a byte at a random offset
  - ByteSpliceMutator    : splice a byte range from a donor corpus entry

HDHunter Reference:
    hdhunter/src/mutators/byte.rs
"""

import random
from typing import Optional


def byte_insert(data: bytes) -> bytes:
    """
    Inserts a single random byte at a random offset.

    Mirrors: ByteInsertMutator (byte.rs)
    """
    if not data:
        return data
    idx  = random.randrange(len(data))
    byte = random.randint(0, 255)
    return data[:idx] + bytes([byte]) + data[idx:]


def byte_remove(data: bytes) -> bytes:
    """
    Removes the byte at a random offset.

    Mirrors: ByteRemoveMutator (byte.rs)
    """
    if not data:
        return data
    idx = random.randrange(len(data))
    return data[:idx] + data[idx + 1:]


def byte_duplicate(data: bytes) -> bytes:
    """
    Duplicates (copies one position forward) the byte at a random offset.

    Mirrors: ByteDuplicateMutator (byte.rs)
    """
    if not data:
        return data
    idx = random.randrange(len(data))
    return data[:idx] + bytes([data[idx]]) + data[idx:]


def byte_splice(data: bytes, donor: bytes, max_size: Optional[int] = None) -> bytes:
    """
    Splices a random sub-range of bytes from the donor into a random
    position in the current payload.

    Mirrors: ByteSpliceMutator (byte.rs)

    Args:
        data:      Target HTTP payload (bytes).
        donor:     Source corpus entry to borrow bytes from.
        max_size:  Upper bound for total output size (matches HDHunter's HasMaxSize).
    """
    if not data or not donor:
        return data

    cap = max_size if max_size else max(len(data) * 2, 4096)
    budget = cap - len(data)
    if budget <= 0:
        return data

    # Sample a slice of the donor
    d_start = random.randrange(len(donor))
    d_end   = random.randint(d_start + 1, min(d_start + budget, len(donor)))
    chunk   = donor[d_start:d_end]

    insert_pos = random.randrange(len(data))
    return data[:insert_pos] + chunk + data[insert_pos:]


# ── HTTP-aware byte perturbation helpers ──────────────────────────────────────
#
# Not in HDHunter's byte.rs, but implemented here to cover common Desync
# vectors that arise from byte-level anomalies in specific header positions.

def obfuscate_transfer_encoding(data: bytes) -> bytes:
    """
    Injects a byte-level obfuscation into the Transfer-Encoding header value,
    one of the core desync triggers:
        - Prepend a space or tab before the value
        - Replace the colon with 'colon + whitespace'
        - Append a trailing invisible character (\x00, \r, etc.)
    """
    marker = b"Transfer-Encoding:"
    if marker not in data and b"transfer-encoding:" not in data.lower():
        return data

    mutations = [
        (b"Transfer-Encoding:", b"Transfer-Encoding : "),   # space before colon
        (b"Transfer-Encoding:", b"Transfer-Encoding\t:"),   # tab before colon
        (b"Transfer-Encoding:", b" Transfer-Encoding:"),    # leading space (folding)
        (b"Transfer-Encoding:", b"Transfer-Encoding:\x00"), # null byte injection
        (b"Transfer-Encoding:", b"TRANSFER-ENCODING:"),     # case mutation
    ]
    key, replacement = random.choice(mutations)
    return data.replace(key, replacement, 1)


def perturb_content_length(data: bytes) -> bytes:
    """
    Replaces the numeric value of Content-Length with a structurally deviant
    representation to confuse parsers (matches HDHunter's 'number' token list).
    """
    marker = b"Content-Length:"
    if marker not in data:
        return data

    # Deviant number tokens from tokens.json
    deviant_numbers = [b"0x10", b"+10", b"-10", b"10.0", b"10e0", b"1_0", b" 10"]
    
    idx = data.find(marker)
    line_end = data.find(b"\r\n", idx)
    if line_end == -1:
        return data
    
    replacement_value = random.choice(deviant_numbers)
    new_line = marker + b" " + replacement_value
    return data[:idx] + new_line + data[line_end:]


# -------------- Unit Tests --------------
if __name__ == "__main__":
    raw = (
        b"POST /post HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Length: 4\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"BODY"
    )
    donor = b"GET / HTTP/1.1\r\nHost: donor.com\r\n\r\n"

    print("=== Byte-Level Mutator Demo ===\n")
    tests = [
        ("byte_insert",               byte_insert(raw)),
        ("byte_remove",               byte_remove(raw)),
        ("byte_duplicate",            byte_duplicate(raw)),
        ("byte_splice",               byte_splice(raw, donor)),
        ("obfuscate_transfer_encoding", obfuscate_transfer_encoding(raw)),
        ("perturb_content_length",    perturb_content_length(raw)),
    ]

    for name, result in tests:
        print(f"[{name}]  ({len(result)} bytes)")
        print(result.decode("latin-1", errors="replace"))
        print()

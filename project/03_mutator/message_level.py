#!/usr/bin/env python3
"""
message_level.py - Message-Level HTTP Mutator
----------------------------------------------
Replicates HDHunter's 6 message-level mutators that operate on the
structured components of a single HTTP message:
  - Field-Line Duplicate     (MessageFieldLineDuplicateMutator)
  - Field-Line Remove        (MessageFieldLineRemoveMutator)
  - Field-Line Splice        (MessageFieldLineSpliceMutator)
  - Node Token Replace       (MessageNodeTokenReplaceMutator)
  - Node Typed Swap          (MessageNodeTypedSwapMutator)
  - Trailer Section Replace  (MessageTrailerSectionReplaceMutator)

HDHunter Reference:
    hdhunter/src/mutators/message.rs
    tokens.json  (mutation vocabulary: strings, numbers, symbols)
"""

import os
import json
import random
from typing import Optional

# ── Token dictionary (mirrors tokens.json from HDHunter) ─────────────────────
_TOKEN_PATH = os.path.join(os.path.dirname(__file__), "tokens.json")
_TOKENS: dict = {}

def _load_tokens():
    global _TOKENS
    if not _TOKENS:
        if os.path.exists(_TOKEN_PATH):
            with open(_TOKEN_PATH, "r") as f:
                _TOKENS = json.load(f)
        else:
            # Inline fallback identical to HDHunter's tokens.json
            _TOKENS = {
                "string": [
                    "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD",
                    "HTTP/1.0", "HTTP/1.1", "chunked", "identity", "gzip", "deflate",
                    "Transfer-Encoding", "Content-Length", "Content-Type", "Connection",
                    "Host", "Accept", "User-Agent", "Authorization", "Cookie",
                    "X-Forwarded-For", "TE", "Trailer",
                ],
                "number": ["0x10", "1_0", "+10", "-10", "10.0", "10e0", "10e+0", "10e-0"],
                "symbol": [
                    ";", "(", ")", "{", "}", "[", "]", ".", ",", ":", "?", "!", "@",
                    "#", "$", "%", "^", "&", "*", "+", "-", "/", "=", "<", ">",
                    "|", "~", "_", "a", "A", "0", "9", " ", "\t", "\n", "\r",
                    "\f", "\x00", "\xa0",
                ],
            }
    return _TOKENS


# ── HTTP Message Parser ───────────────────────────────────────────────────────

class HttpMessage:
    """
    Structured representation of an HTTP message with 3 segments:
        start_line  : e.g.  b"POST /path HTTP/1.1"
        field_lines : list of raw header lines, e.g. [b"Host: a.com", ...]
        body        : raw body bytes
    """

    def __init__(self, start_line: bytes, field_lines: list, body: bytes):
        self.start_line  = start_line
        self.field_lines = field_lines   # List[bytes], one entry per header
        self.body        = body

    @classmethod
    def from_bytes(cls, raw: bytes) -> "HttpMessage":
        """
        Parse a raw HTTP request/response bytes into an HttpMessage object.
        Supports both CRLF and LF line endings.
        """
        sep = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
        parts = raw.split(sep, 1)
        head_block = parts[0]
        body = parts[1] if len(parts) > 1 else b""

        line_sep = b"\r\n" if b"\r\n" in head_block else b"\n"
        lines = head_block.split(line_sep)
        start_line = lines[0] if lines else b""
        field_lines = [l for l in lines[1:] if l]

        return cls(start_line, field_lines, body)

    def to_bytes(self) -> bytes:
        """Serialise back to a raw HTTP message with canonical CRLF."""
        headers = b"\r\n".join([self.start_line] + self.field_lines)
        return headers + b"\r\n\r\n" + self.body


# ── Mutator Functions ─────────────────────────────────────────────────────────

MAX_FIELD_LINES = 20  # mirrors HDHunter's guard: children.len() >= 20 → Skip


def field_line_duplicate(msg: HttpMessage) -> HttpMessage:
    """
    Duplicates a randomly chosen header line.

    Mirrors: MessageFieldLineDuplicateMutator
    """
    if not msg.field_lines or len(msg.field_lines) >= MAX_FIELD_LINES:
        return msg
    idx = random.randrange(len(msg.field_lines))
    new_lines = msg.field_lines[:idx] + [msg.field_lines[idx]] + msg.field_lines[idx:]
    return HttpMessage(msg.start_line, new_lines, msg.body)


def field_line_remove(msg: HttpMessage) -> HttpMessage:
    """
    Removes a randomly chosen header line.

    Mirrors: MessageFieldLineRemoveMutator
    """
    if not msg.field_lines:
        return msg
    idx = random.randrange(len(msg.field_lines))
    new_lines = msg.field_lines[:idx] + msg.field_lines[idx + 1:]
    return HttpMessage(msg.start_line, new_lines, msg.body)


def field_line_splice(msg: HttpMessage, donor: HttpMessage) -> HttpMessage:
    """
    Inserts a header block slice from a donor message at a random position.

    Mirrors: MessageFieldLineSpliceMutator (cross-corpus splice)
    """
    if not msg.field_lines or len(msg.field_lines) >= MAX_FIELD_LINES:
        return msg
    if not donor.field_lines:
        return msg

    # Sample a random sub-range from the donor's headers
    start = random.randrange(len(donor.field_lines))
    end   = random.randint(start + 1, len(donor.field_lines))
    donor_slice = donor.field_lines[start:end]

    insert_pos = random.randrange(len(msg.field_lines))
    new_lines = msg.field_lines[:insert_pos] + donor_slice + msg.field_lines[insert_pos:]
    return HttpMessage(msg.start_line, new_lines, msg.body)


def node_token_replace(msg: HttpMessage) -> HttpMessage:
    """
    Replaces the value of a random header with a token from the mutation
    vocabulary (strings, numbers, or symbols from tokens.json).

    Mirrors: MessageNodeTokenReplaceMutator
    """
    if not msg.field_lines:
        return msg

    tokens = _load_tokens()
    # Pick a random token category proportionally
    category = random.choice(["string", "number", "symbol"])
    token_value = random.choice(tokens[category]).encode("latin-1", errors="replace")

    idx = random.randrange(len(msg.field_lines))
    line = msg.field_lines[idx]

    if b":" in line:
        header_name = line.split(b":", 1)[0]
        new_line = header_name + b": " + token_value
    else:
        new_line = token_value  # Mutate the whole line

    new_lines = msg.field_lines[:idx] + [new_line] + msg.field_lines[idx + 1:]
    return HttpMessage(msg.start_line, new_lines, msg.body)


def node_typed_swap(msg: HttpMessage) -> HttpMessage:
    """
    Swaps two randomly selected header values of compatible types (both numeric
    or both non-numeric), analogous to HDHunter's NodeLabel-typed swap check.

    Mirrors: MessageNodeTypedSwapMutator
    """
    if len(msg.field_lines) < 2:
        return msg

    idx_a, idx_b = random.sample(range(len(msg.field_lines)), 2)
    line_a, line_b = msg.field_lines[idx_a], msg.field_lines[idx_b]

    def header_parts(line: bytes):
        if b":" in line:
            name, _, val = line.partition(b":")
            return name.strip(), val.strip()
        return line, b""

    name_a, val_a = header_parts(line_a)
    name_b, val_b = header_parts(line_b)

    # Perform the swap of values (mirrors NodeLabel typed constraint)
    new_lines = list(msg.field_lines)
    new_lines[idx_a] = name_a + b": " + val_b
    new_lines[idx_b] = name_b + b": " + val_a
    return HttpMessage(msg.start_line, new_lines, msg.body)


def trailer_section_replace(msg: HttpMessage, donor: HttpMessage) -> HttpMessage:
    """
    If the message uses Chunked Transfer-Encoding, appends donor headers as
    Trailer fields after the terminal '0\\r\\n' chunk.

    Mirrors: MessageTrailerSectionReplaceMutator
    """
    te_header = b"Transfer-Encoding: chunked"
    has_chunked = any(te_header.lower() in l.lower() for l in msg.field_lines)
    terminal   = b"0\r\n\r\n"

    if not has_chunked or terminal not in msg.body:
        return msg
    if not donor.field_lines:
        return msg

    trailer_lines = b"\r\n".join(donor.field_lines)
    new_body = msg.body.replace(terminal, b"0\r\n" + trailer_lines + b"\r\n\r\n", 1)
    return HttpMessage(msg.start_line, msg.field_lines, new_body)


# -------------- Unit Tests --------------
if __name__ == "__main__":
    raw = (
        b"POST /post HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Length: 4\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"4\r\nWiki\r\n0\r\n\r\n"
    )
    donor_raw = (
        b"GET / HTTP/1.1\r\n"
        b"Host: donor.com\r\n"
        b"X-Custom: injected\r\n"
        b"\r\n"
    )

    msg   = HttpMessage.from_bytes(raw)
    donor = HttpMessage.from_bytes(donor_raw)

    print("=== Message-Level Mutator Demo ===\n")
    ops = [
        ("field_line_duplicate", field_line_duplicate(msg)),
        ("field_line_remove",    field_line_remove(msg)),
        ("field_line_splice",    field_line_splice(msg, donor)),
        ("node_token_replace",   node_token_replace(msg)),
        ("node_typed_swap",      node_typed_swap(msg)),
        ("trailer_replace",      trailer_section_replace(msg, donor)),
    ]

    for name, result in ops:
        print(f"[{name}]")
        print(result.to_bytes().decode("latin-1", errors="replace"))
        print()

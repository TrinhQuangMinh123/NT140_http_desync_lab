#!/usr/bin/env python3
"""
diff_checker.py - State Tuple Differential Analyzer
-----------------------------------------------------
Adapts HDHunter's HttpParamFeedback.is_interesting() idea in Python.

HDHunter Reference:
    hdhunter/src/feedbacks/http_param.rs (lines 86-97)

The 7 State Tuple fields compared are HDHunter-inspired, but the source
of truth is externally observed socket/backend JSON data rather than
instrumented parser state from shared memory:

    Field                  | HDHunter                    | Our Source
    -----------------------|-----------------------------|---------------------------
    1. status              | p1.status[i]                | HTTP status line from socket
    2. message_count       | p1.message_count            | # responses received
    3. message_processed   | p1.message_processed        | # complete messages parsed
    4. content_length      | p1.content_length[i]        | backend JSON: content_length
    5. transfer_encoding   | p1.chunked_encoding[i]      | backend JSON: transfer_encoding
    6. body_length         | p1.body_length[i]           | backend JSON: body_length
    7. consumed_length     | p1.consumed_length[i]       | len(raw response body)
"""

from dataclasses import dataclass, field
from typing import Optional
import json


@dataclass
class StateTuple:
    """
    Parsed HTTP state as seen by one endpoint (proxy or backend direct).
    Lightweight adaptation of HDHunter's HttpParam struct from hdhunter-rt.
    """
    # Field 1: HTTP status code (0 = timeout/connection error)
    status: int = 0

    # Field 2: Number of HTTP response messages received
    message_count: int = 0

    # Field 3: Number of complete messages fully parsed
    message_processed: int = 0

    # Field 4: Content-Length header value as seen by backend (-1 = absent)
    content_length: int = -1

    # Field 5: Transfer-Encoding (True = chunked, False = not, None = absent)
    transfer_encoding: Optional[bool] = None

    # Field 6: Actual body bytes consumed by the backend
    body_length: int = 0

    # Field 7: Total raw bytes in the response body from the proxy/server
    consumed_length: int = 0

    # Field 8 (paper §4.4.1 "Order"): list of X-Desync-Id values in order received.
    # Populated from response headers; empty if no pipelining/UUID injection used.
    order: list = field(default_factory=list)

    # Field 9 (paper §4.4.1 "Body" content): sha256[:16] of body bytes the backend
    # actually consumed. Catches content discrepancies even when length matches.
    body_hash: str = ""

    # A5: was there data left over in wsgi.input after the main read?
    # True = clean EOF (backend agrees with CL), False = leftover bytes in stream.
    # None = unknown / not provided by backend.
    wsgi_eof: Optional[bool] = None

    # Extra context (not in HDHunter, but useful for reporting)
    timed_out: bool = False
    raw_response: bytes = field(default_factory=bytes, repr=False)
    backend_json: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_raw_response(cls, raw_response: bytes, timed_out: bool = False) -> "StateTuple":
        """
        Parse a raw HTTP response from a TCP socket into a StateTuple.
        """
        st = cls()
        st.raw_response = raw_response
        st.timed_out = timed_out
        st.consumed_length = len(raw_response)

        if not raw_response:
            st.status = 0
            return st

        try:
            text = raw_response.decode("latin-1")

            # Count how many HTTP responses are bundled (pipelining/smuggling)
            import re
            status_lines = re.findall(r"HTTP/1\.[01] (\d{3})", text)
            st.message_count = len(status_lines)
            st.message_processed = len(status_lines)

            if status_lines:
                st.status = int(status_lines[0])

            # A1: Order — extract every X-Desync-Id header in arrival order.
            # Paper §4.4.1: Order = collection of X-Desync-Id values, used to
            # detect response reordering (Response Stealing candidate).
            order_matches = re.findall(
                r"^X-Desync-Id:\s*([^\r\n]+)",
                text,
                flags=re.IGNORECASE | re.MULTILINE,
            )
            st.order = [v.strip() for v in order_matches]

            # Try to parse the JSON body(ies) from our backend app.
            # When pipelining, multiple JSON bodies may appear back-to-back.
            # We aggregate body_length/body_hash across all parsed messages.
            json_bodies = _extract_json_bodies(text)

            if json_bodies:
                # Use the first message's CL/TE for the primary fields (paper
                # treats Encoding/CL per-message; for our simplified scalar
                # tuple we pick the first message — pipeline mismatch is caught
                # by Rule 1/Rule 8 anyway).
                first = json_bodies[0]
                st.backend_json = first

                cl = first.get("cl_env") or first.get("content_length")
                st.content_length = int(cl) if cl not in (None, "") else -1

                te = first.get("transfer_encoding")
                st.transfer_encoding = (
                    None if te is None else ("chunked" in te.lower())
                )

                # Aggregate body_length + body_hash across all messages so
                # smuggled requests that reach the backend show up here.
                total_body = 0
                hash_concat = ""
                for d in json_bodies:
                    total_body += int(d.get("body_length", 0))
                    hash_concat += str(d.get("body_hash", ""))
                st.body_length = total_body
                st.body_hash = hash_concat

                # A5: wsgi_eof — if ANY message reported leftover bytes,
                # treat the whole exchange as non-clean.
                eof_flags = [d.get("wsgi_eof") for d in json_bodies
                             if "wsgi_eof" in d]
                if eof_flags:
                    st.wsgi_eof = all(bool(f) for f in eof_flags)

        except Exception:
            pass

        return st


def _extract_json_bodies(text: str) -> list:
    """
    Extract every JSON object emitted by the backend app from a raw response
    that may contain multiple pipelined responses concatenated together.

    Returns a list of dicts (one per parsed message). Empty list if none found.
    """
    import re
    results = []
    # Split on each HTTP status line — each segment is one response.
    parts = re.split(r"(?=HTTP/1\.[01] \d{3})", text)
    for part in parts:
        if "\r\n\r\n" not in part:
            continue
        body_text = part.split("\r\n\r\n", 1)[1]
        body_text = _strip_chunked_envelope(body_text)
        # Find the JSON object inside the body
        start = body_text.find("{")
        if start < 0:
            continue
        # Try progressively shorter substrings until JSON parses
        for end in range(len(body_text), start, -1):
            candidate = body_text[start:end].strip()
            if not candidate.endswith("}"):
                continue
            try:
                results.append(json.loads(candidate))
                break
            except json.JSONDecodeError:
                continue
    return results


def _strip_chunked_envelope(text: str) -> str:
    """Remove chunked transfer encoding wrapper if present."""
    import re
    # If the response body starts with a hex chunk size, strip it
    if re.match(r'^[0-9a-fA-F]+\r\n', text):
        lines = text.split("\r\n")
        body_lines = []
        i = 0
        while i < len(lines):
            try:
                size = int(lines[i], 16)
                if size == 0:
                    break
                i += 1
                body_lines.append(lines[i])
                i += 1
            except (ValueError, IndexError):
                body_lines.append(lines[i])
                i += 1
        return "\r\n".join(body_lines)
    return text


# ── HDHunter-Inspired Rule Constants ──────────────────────────────────────────

def _is_error(status: int) -> bool:
    """
    Adaptation of HDHunter's is_error! macro: status 0 (timeout) or 4xx/5xx are errors.
    When BOTH endpoints return error, body_length/chunked/cl/consumed are skipped.
    """
    return status == 0 or (400 <= status < 600)


@dataclass
class DiffResult:
    """Result of comparing two StateTuples."""
    is_discrepancy: bool
    triggered_rules: list
    proxy: StateTuple
    direct: StateTuple


def compare(proxy: StateTuple, direct: StateTuple) -> DiffResult:
    """
    Apply the 7 adapted differential rules from HttpParamFeedback.is_interesting().

    Returns a DiffResult indicating whether a parsing discrepancy was detected.
    """
    triggered = []

    # ── Rule 1: Message Count Mismatch ───────────────────────────────────────
    # HDHunter: rule!(p1.message_count != p2.message_count)
    if proxy.message_count != direct.message_count:
        triggered.append({
            "rule": 1,
            "field": "message_count",
            "proxy": proxy.message_count,
            "direct": direct.message_count,
            "note": "Pipeline desync candidate: endpoints saw different numbers of HTTP messages",
        })

    # ── Rule 2: Message Processed Mismatch ───────────────────────────────────
    # HDHunter: rule!(p1.message_processed != p2.message_processed)
    if proxy.message_processed != direct.message_processed:
        triggered.append({
            "rule": 2,
            "field": "message_processed",
            "proxy": proxy.message_processed,
            "direct": direct.message_processed,
            "note": "One endpoint processed more complete messages than the other",
        })

    # ── Rules 3–7: Per-message fields (skip if BOTH are error responses) ─────
    both_error = _is_error(proxy.status) and _is_error(direct.status)

    # ── Rule 3: HTTP Status Mismatch ─────────────────────────────────────────
    if proxy.status != direct.status:
        triggered.append({
            "rule": 3,
            "field": "status",
            "proxy": proxy.status,
            "direct": direct.status,
            "note": "Proxy and backend returned different HTTP status codes",
        })

    # ── Rule 6: Body Length Mismatch ─────────────────────────────────────────
    # Paper §4.4.2: Body is compared directly regardless of error state.
    # HDHunter: rule!(p1.body_length[i] != p2.body_length[i])
    if proxy.body_length != direct.body_length:
        triggered.append({
            "rule": 6,
            "field": "body_length",
            "proxy": proxy.body_length,
            "direct": direct.body_length,
            "note": "Backend consumed different body bytes via proxy vs direct",
        })

    # ── Rule 8: Order Mismatch (paper §4.4.1 — X-Desync-Id collection) ───────
    # Triggers when the sequence of X-Desync-Id headers across responses
    # differs between the two paths. Strong signal for Response Stealing /
    # disordered pipelined responses.
    if proxy.order != direct.order:
        triggered.append({
            "rule": 8,
            "field": "order",
            "proxy": proxy.order,
            "direct": direct.order,
            "note": "Response order (X-Desync-Id sequence) differs — Response Stealing candidate",
        })

    # ── Rule 9: Body Content Hash Mismatch (paper §4.4.1 — Body content) ─────
    # Catches content discrepancies that body_length alone misses: same
    # number of bytes consumed but different bytes (e.g. TE.CL with body
    # offset shifted).
    if proxy.body_hash and direct.body_hash and proxy.body_hash != direct.body_hash:
        triggered.append({
            "rule": 9,
            "field": "body_hash",
            "proxy": proxy.body_hash,
            "direct": direct.body_hash,
            "note": "Backend consumed same length but different content — TE.CL offset candidate",
        })

    if not both_error:
        # Paper §4.4.2: Encoding/CL/Consumed only meaningful if not both 4xx/5xx.
        # ── Rule 4: Chunked / Transfer-Encoding Mismatch ─────────────────────
        # HDHunter: rule!(p1.chunked_encoding[i] != p2.chunked_encoding[i])
        if proxy.transfer_encoding != direct.transfer_encoding:
            triggered.append({
                "rule": 4,
                "field": "transfer_encoding (chunked)",
                "proxy": proxy.transfer_encoding,
                "direct": direct.transfer_encoding,
                "note": "Transfer-Encoding handling differs between the two paths",
            })

        # ── Rule 5: Content-Length Mismatch ──────────────────────────────────
        # HDHunter: rule!(p1.content_length[i] != p2.content_length[i])
        if proxy.content_length != direct.content_length:
            triggered.append({
                "rule": 5,
                "field": "content_length",
                "proxy": proxy.content_length,
                "direct": direct.content_length,
                "note": "Content-Length handling differs between the two paths",
            })

        # ── Rule 7: Consumed Length Mismatch ─────────────────────────────────
        # HDHunter: rule!(p1.consumed_length[i] != p2.consumed_length[i])
        if proxy.consumed_length != direct.consumed_length:
            triggered.append({
                "rule": 7,
                "field": "consumed_length",
                "proxy": proxy.consumed_length,
                "direct": direct.consumed_length,
                "note": "Raw response size differs; response-side candidate requires replay",
            })

    return DiffResult(
        is_discrepancy=len(triggered) > 0,
        triggered_rules=triggered,
        proxy=proxy,
        direct=direct,
    )


def print_comparison(result: DiffResult, payload_label: str = ""):
    """
    Pretty-print the full state tuple comparison for both endpoints.
    """
    RESET  = "\033[0m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"

    label = f" [{payload_label}]" if payload_label else ""
    print(f"\n{'─'*70}")
    print(f"{BOLD}{'🔴 DISCREPANCY' if result.is_discrepancy else '🟢 SAME'}{label}{RESET}")
    print(f"{'─'*70}")

    headers = ["Field", "Proxy Path", "Backend Direct"]
    rows = [
        ("1. status",            result.proxy.status,            result.direct.status),
        ("2. message_count",     result.proxy.message_count,     result.direct.message_count),
        ("3. message_processed", result.proxy.message_processed, result.direct.message_processed),
        ("4. content_length",    result.proxy.content_length,    result.direct.content_length),
        ("5. transfer_encoding", result.proxy.transfer_encoding, result.direct.transfer_encoding),
        ("6. body_length",       result.proxy.body_length,       result.direct.body_length),
        ("7. consumed_length",   result.proxy.consumed_length,   result.direct.consumed_length),
        ("8. order",             result.proxy.order,             result.direct.order),
        ("9. body_hash",         result.proxy.body_hash,         result.direct.body_hash),
        ("   wsgi_eof",          result.proxy.wsgi_eof,          result.direct.wsgi_eof),
    ]

    col_w = [28, 22, 22]
    header_line = f"  {headers[0]:<{col_w[0]}} {headers[1]:<{col_w[1]}} {headers[2]:<{col_w[2]}}"
    print(f"{CYAN}{header_line}{RESET}")
    print(f"  {'─'*68}")

    triggered_fields = {r["field"] for r in result.triggered_rules}
    for field_name, pval, dval in rows:
        # Highlight rows where values differ
        short_field = field_name.split(". ", 1)[1] if ". " in field_name else field_name
        color = RED if short_field in triggered_fields else ""
        end   = RESET if color else ""
        print(f"  {color}{field_name:<{col_w[0]}} {str(pval):<{col_w[1]}} {str(dval):<{col_w[2]}}{end}")

    if result.is_discrepancy:
        print(f"\n{YELLOW}  Triggered Rules:{RESET}")
        for r in result.triggered_rules:
            print(f"    Rule {r['rule']} ({r['field']}): {r['note']}")

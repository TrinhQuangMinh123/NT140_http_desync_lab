#!/usr/bin/env python3
"""
diff_checker.py - Observed Response Tuple Differential Analyzer
----------------------------------------------------------------
IMPORTANT: this module compares EXTERNALLY OBSERVED state, NOT internal
parser state. Paper HDHUNTER §4.4.1 extracts true parser state via code
insertion (e.g. internal Consumed counter, internal Count). We can only
inspect what shows up on the wire (raw socket bytes) plus what the
backend WSGI gateway chooses to expose in its JSON response. Therefore
the fields below are observed-equivalents, not parser-internal values.

HDHunter Reference:
    hdhunter/src/feedbacks/http_param.rs (lines 86-97)

    Paper StateTuple field | Our observed-source                          | Notes
    -----------------------|----------------------------------------------|------------------------
    Status                 | first status line of raw response            | OK, close to paper
    Count                  | number of `HTTP/1.x NNN` lines seen          | observed_response_count
    (n/a, ours)            | number of bodies parsed                      | observed_messages_parsed
    Content-Length         | backend JSON: cl_env (WSGI-level)            | WSGI's view, NOT parser
    Transfer-Encoding      | backend JSON: HTTP_TRANSFER_ENCODING         | WSGI's view, NOT parser
    Body                   | backend JSON: body_length (bytes WSGI read)  | post-decode, not parser
    Consumed               | len(raw_response) from socket                | raw_response_length
    Order                  | echoed X-Desync-Id list from response        | observed-only
    Body content           | backend JSON: sha256[:16] of body            | post-decode hash

Internally we still call the fields by their paper-equivalent names so
the code reads like HDHunter, but the renamed convenience properties
(observed_response_count, raw_response_length, …) emphasize what they
really are when discussed in reports.
"""

from dataclasses import dataclass, field
from typing import Optional
import json


@dataclass
class StateTuple:
    """
    OBSERVED response tuple from one endpoint (proxy or backend-direct).
    NOT parser-internal state — see module docstring for the distinction.
    """
    # Field 1: HTTP status code parsed from the first response line.
    # 0 = timeout / connection error / no status line seen.
    status: int = 0

    # Field 2: Number of `HTTP/1.x NNN` status lines we observed in the raw
    # response stream. Approximates paper's "Count" (parser internal) but is
    # really `observed_response_count`.
    message_count: int = 0

    # Field 3: Number of complete responses we managed to fully parse.
    # Same source as message_count for now; mainly differs when partial
    # framing breaks parsing of later messages.
    message_processed: int = 0

    # Field 4: Content-Length as exposed by the BACKEND WSGI environ
    # (`CONTENT_LENGTH`). This is WSGI-level, not the raw header byte the
    # parser saw before normalization. -1 = absent in environ.
    content_length: int = -1

    # Field 5: Transfer-Encoding chunked flag derived from
    # `HTTP_TRANSFER_ENCODING` environ. WSGI-level view, may be normalized
    # by Gunicorn before reaching us.
    transfer_encoding: Optional[bool] = None

    # Field 6: Body length as measured by `len(wsgi.input.read())`. This is
    # post-decode (chunked → raw), NOT raw body bytes on the wire.
    body_length: int = 0

    # Field 7: Total raw bytes the fuzzer received on the socket. This is
    # the WIRE response length, not the parser's internal Consumed counter.
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

    # #3 Coverage feedback (Python backend only, paper §4.2.3 approximation).
    # cov_new_edges = number of NEW (file, line) pairs this request hit
    # versus prior accumulated coverage on the backend. None = no instrumentation.
    cov_new_edges: Optional[int] = None
    cov_total_edges: Optional[int] = None

    # Extra context (not in HDHunter, but useful for reporting)
    timed_out: bool = False
    # True if the socket reported timeout *after* receiving some bytes but
    # before the response was clearly complete. Caller may want to treat
    # such replies as suspect (paper §4.3-style stable input requirement).
    partial_timeout: bool = False
    raw_response: bytes = field(default_factory=bytes, repr=False)
    backend_json: dict = field(default_factory=dict, repr=False)

    # ── Honest aliases (for reports / slides) ────────────────────────────
    # These properties exist so write-ups can refer to the fields by names
    # that don't imply parser-internal measurement.
    @property
    def observed_response_count(self) -> int:
        return self.message_count

    @property
    def observed_messages_parsed(self) -> int:
        return self.message_processed

    @property
    def raw_response_length(self) -> int:
        return self.consumed_length

    @property
    def wsgi_content_length(self) -> int:
        return self.content_length

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

                # CL parse — paper §5.2.1 calls out non-standard numbers
                # ("0x10", "+10", "00011", "1_0", "10abc", …). Python's
                # int() is too lenient (it accepts "+10", " 10 ", "1_0"
                # via the underscore literal handling, etc.), so we use a
                # strict decimal regex instead. Anything non-conforming is
                # flagged with the -2 sentinel and the raw token is stored.
                cl = first.get("cl_env") or first.get("content_length")
                if cl in (None, ""):
                    st.content_length = -1
                else:
                    cl_str = str(cl)
                    if re.fullmatch(r"[0-9]+", cl_str):
                        # Pure decimal digits (incl. zero padding "00011" —
                        # int() still produces 11 but we keep the raw form
                        # in the backend JSON so the report shows it).
                        try:
                            st.content_length = int(cl_str)
                        except ValueError:
                            st.content_length = -2
                            st.backend_json["raw_cl_unparsed"] = cl_str
                    else:
                        # Non-standard token: 0x10, +10, -1, 1_0, 10abc, ...
                        st.content_length = -2
                        st.backend_json["raw_cl_unparsed"] = cl_str

                te = first.get("transfer_encoding")
                st.transfer_encoding = (
                    None if te is None else ("chunked" in te.lower())
                )

                # Aggregate body_length + body_hash across all messages so
                # smuggled requests that reach the backend show up here.
                # int() on body_length is wrapped per-message — a flaky
                # body_length should not lose body_hash/wsgi_eof signals.
                total_body = 0
                hash_concat = ""
                for d in json_bodies:
                    try:
                        total_body += int(d.get("body_length", 0))
                    except (ValueError, TypeError):
                        pass
                    hash_concat += str(d.get("body_hash", ""))
                st.body_length = total_body
                st.body_hash = hash_concat

                # A5: wsgi_eof — if ANY message reported leftover bytes,
                # treat the whole exchange as non-clean.
                eof_flags = [d.get("wsgi_eof") for d in json_bodies
                             if "wsgi_eof" in d]
                if eof_flags:
                    st.wsgi_eof = all(bool(f) for f in eof_flags)

                # #3 Coverage feedback fields — also isolated, in case the
                # backend emits a non-numeric placeholder.
                cov_new = first.get("cov_new_edges")
                if cov_new is not None:
                    try:
                        st.cov_new_edges = int(cov_new)
                    except (ValueError, TypeError):
                        st.cov_new_edges = None
                cov_tot = first.get("cov_total_edges")
                if cov_tot is not None:
                    try:
                        st.cov_total_edges = int(cov_tot)
                    except (ValueError, TypeError):
                        st.cov_total_edges = None

        except Exception:
            # Outer fallback: malformed response (bad UTF, broken JSON, ...).
            # State remains at whatever was filled in before the exception.
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
    """Result of comparing two StateTuples.

    `confidence` reflects how trustworthy the rule set is:
      - "high"   : both sides closed cleanly, no partial reads.
      - "low"    : at least one side hit socket timeout after partial
                   bytes (paper §4.3-style stability concern). Length-only
                   rules (R7 raw_response_length) are especially unreliable
                   here, so they are suppressed by `compare()`.
    """
    is_discrepancy: bool
    triggered_rules: list
    proxy: StateTuple
    direct: StateTuple
    confidence: str = "high"
    notes: list = field(default_factory=list)


def compare(proxy: StateTuple, direct: StateTuple) -> DiffResult:
    """
    Apply the 7 adapted differential rules from HttpParamFeedback.is_interesting().

    Returns a DiffResult indicating whether a parsing discrepancy was detected.
    """
    triggered = []
    # Detect partial-read condition: at least one side timed out after
    # receiving some bytes. Treats such samples as low-confidence — Rule 7
    # in particular is suppressed because raw_response_length will then
    # mostly reflect socket timing, not parser disagreement.
    partial = bool(getattr(proxy, "partial_timeout", False) or
                   getattr(direct, "partial_timeout", False))
    confidence = "low" if partial else "high"
    diff_notes: list = []
    if partial:
        diff_notes.append(
            "partial_timeout=True on at least one side — "
            "raw_response_length (Rule 7) suppressed, "
            "treat remaining signals as needing replay confirmation"
        )

    # ── Rule 1: Observed Response Count Mismatch ─────────────────────────────
    # HDHunter: rule!(p1.message_count != p2.message_count) — paper measures
    # parser-internal Count. We measure observed_response_count (HTTP/1.x
    # status lines on the wire), which is an OBSERVATION, not parser state.
    if proxy.message_count != direct.message_count:
        triggered.append({
            "rule": 1,
            "field": "observed_response_count",
            "proxy": proxy.message_count,
            "direct": direct.message_count,
            "note": "Pipeline desync candidate: paths emitted a different number of HTTP responses on the wire",
        })

    # ── Rule 2: Fully-Parsed Response Count Mismatch ─────────────────────────
    if proxy.message_processed != direct.message_processed:
        triggered.append({
            "rule": 2,
            "field": "observed_messages_parsed",
            "proxy": proxy.message_processed,
            "direct": direct.message_processed,
            "note": "One path produced more fully-parseable responses than the other",
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
        # Sentinel -2 means the backend emitted a non-decimal CL token
        # (e.g. "0x10", "+10"); when one side is -2 and the other isn't,
        # that's paper §5.2.1 non-standard number parsing in action.
        if proxy.content_length != direct.content_length:
            note = "Content-Length handling differs between the two paths"
            if -2 in (proxy.content_length, direct.content_length):
                raw_p = proxy.backend_json.get("raw_cl_unparsed")
                raw_d = direct.backend_json.get("raw_cl_unparsed")
                note += (f" — non-decimal CL observed "
                         f"(proxy_raw={raw_p!r}, direct_raw={raw_d!r}); "
                         f"paper §5.2.1 candidate")
            triggered.append({
                "rule": 5,
                "field": "wsgi_content_length",
                "proxy": proxy.content_length,
                "direct": direct.content_length,
                "note": note,
            })

        # ── Rule 7: Consumed Length Mismatch ─────────────────────────────────
        # HDHunter: rule!(p1.consumed_length[i] != p2.consumed_length[i])
        # Suppressed when partial_timeout — raw response length is dominated
        # by socket timing under partial reads and would be mostly noise.
        if (not partial
                and proxy.consumed_length != direct.consumed_length):
            triggered.append({
                "rule": 7,
                "field": "raw_response_length",
                "proxy": proxy.consumed_length,
                "direct": direct.consumed_length,
                "note": "Raw response size differs; response-side candidate requires replay",
            })

    return DiffResult(
        is_discrepancy=len(triggered) > 0,
        triggered_rules=triggered,
        proxy=proxy,
        direct=direct,
        confidence=confidence,
        notes=diff_notes,
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
    conf_tag = ""
    if getattr(result, "confidence", "high") == "low":
        conf_tag = f" {YELLOW}(confidence=low){RESET}"
    print(f"\n{'─'*70}")
    print(f"{BOLD}{'🔴 DISCREPANCY' if result.is_discrepancy else '🟢 SAME'}{label}{RESET}{conf_tag}")
    if getattr(result, "notes", None):
        for n in result.notes:
            print(f"  {YELLOW}note: {n}{RESET}")
    print(f"{'─'*70}")

    headers = ["Observed Field", "Proxy Path", "Backend Direct"]
    rows = [
        # Field names emphasize OBSERVED nature (paper has parser-internal versions).
        ("1. status (observed)",       result.proxy.status,            result.direct.status),
        ("2. observed_response_count", result.proxy.message_count,     result.direct.message_count),
        ("3. messages_fully_parsed",   result.proxy.message_processed, result.direct.message_processed),
        ("4. wsgi_content_length",     result.proxy.content_length,    result.direct.content_length),
        ("5. wsgi_transfer_encoding",  result.proxy.transfer_encoding, result.direct.transfer_encoding),
        ("6. wsgi_body_length",        result.proxy.body_length,       result.direct.body_length),
        ("7. raw_response_length",     result.proxy.consumed_length,   result.direct.consumed_length),
        ("8. response_order",          result.proxy.order,             result.direct.order),
        ("9. body_hash (wsgi)",        result.proxy.body_hash,         result.direct.body_hash),
        ("   wsgi_eof",                result.proxy.wsgi_eof,          result.direct.wsgi_eof),
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

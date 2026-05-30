"""
backend/app.py - Differential Testing Backend (WSGI)
-----------------------------------------------------
Returns a JSON state tuple so the fuzzer can compare how the proxy
vs direct-backend interpreted the same request.

State tuple fields (HDHunter-inspired):
    cl_env           : CONTENT_LENGTH backend trusts (paper §4.4.1 "CL")
    transfer_encoding: HTTP_TRANSFER_ENCODING backend saw (paper "Encoding")
    body_length      : bytes WSGI.input.read() actually returned (paper "Body" len)
    body_hash        : sha256 of body content, first 16 hex chars (paper "Body" content)
    wsgi_eof         : True if no more data after main read — desync smoke gun
    x_desync_id      : echoed back so fuzzer can reconstruct Order across pipelined msgs
"""

import json
import time
import hashlib

# ── Coverage instrumentation (paper §4.2.3-style, Python side only) ──────────
# Track line coverage per request so the fuzzer can grow its corpus when an
# input exercises previously-unseen edges.  Real HDHUNTER instruments the
# bytecode interpreter via Witcher [47]; we approximate with coverage.py at
# the WSGI layer — enough to claim "semi-gray-box on the backend".
try:
    import coverage  # type: ignore
    _COV = coverage.Coverage(branch=True, data_file=None)
    _COV.start()
    _COV_AVAILABLE = True
except Exception:
    _COV = None
    _COV_AVAILABLE = False

_SEEN_LINES = set()  # process-wide accumulator
_REQ_COUNTER = 0

# ── HDHunter internal-state shim (B4b) ───────────────────────────────────────
# Attach to the runner-provided SysV HttpParam shm (env __HTTP_PARAM). On the
# coverage.py baseline image hdhunter.py is not present / __HTTP_PARAM is unset,
# so this degrades to a no-op.
try:
    import hdhunter as _hdh
    _hdh.hdhunter_init()
except Exception:
    _hdh = None


def _snapshot_coverage():
    """Return the set of (file, line) tuples touched so far."""
    if not _COV_AVAILABLE:
        return set()
    _COV.stop()
    data = _COV.get_data()
    pairs = set()
    for filename in data.measured_files():
        for line in data.lines(filename) or []:
            pairs.add((filename, line))
    _COV.start()
    return pairs


def application(environ, start_response):
    state = {}

    state["host"]              = environ.get("HTTP_HOST")
    state["method"]            = environ.get("REQUEST_METHOD")
    state["path"]              = environ.get("PATH_INFO")
    state["content_length"]    = environ.get("CONTENT_LENGTH")
    state["cl_env"]            = environ.get("CONTENT_LENGTH")
    state["transfer_encoding"] = environ.get("HTTP_TRANSFER_ENCODING")

    try:
        wsgi_in = environ["wsgi.input"]
        raw_body = wsgi_in.read()
        state["body_content"] = raw_body.decode("latin-1", errors="replace")
        state["body_length"]  = len(raw_body)
        state["body_hash"]    = hashlib.sha256(raw_body).hexdigest()[:16]
        state["body_preview"] = raw_body[:64].hex()

        try:
            extra = wsgi_in.read(1)
            state["wsgi_eof"] = (extra == b"")
        except Exception:
            state["wsgi_eof"] = True

        # Body fully consumed -> this message is processed (paper Count rollover).
        if _hdh is not None:
            _hdh.hdhunter_mark_message_processed(_hdh.MODE_REQUEST)
    except Exception as e:
        state["body_content"] = ""
        state["body_length"]  = 0
        state["body_hash"]    = ""
        state["body_preview"] = ""
        state["wsgi_eof"]     = True
        state["read_error"]   = str(e)

    state["x_real_ip"]   = environ.get("HTTP_X_REAL_IP")
    state["x_desync_id"] = environ.get("HTTP_X_DESYNC_ID")
    state["timestamp"]   = time.time()

    # ── Coverage delta for this request ──────────────────────────────────────
    global _REQ_COUNTER, _SEEN_LINES
    _REQ_COUNTER += 1
    if _COV_AVAILABLE:
        after = _snapshot_coverage()
        new_pairs = after - _SEEN_LINES
        _SEEN_LINES = after
        # Only report new edges to keep payload size manageable.
        state["cov_new_edges"]   = len(new_pairs)
        state["cov_total_edges"] = len(after)
        state["cov_request_id"]  = _REQ_COUNTER
    else:
        state["cov_new_edges"]   = None
        state["cov_total_edges"] = None

    response_headers = [("Content-Type", "application/json")]
    if state["x_desync_id"]:
        response_headers.append(("X-Desync-Id", state["x_desync_id"]))

    start_response("200 OK", response_headers)
    return [json.dumps(state, indent=2).encode("utf-8")]

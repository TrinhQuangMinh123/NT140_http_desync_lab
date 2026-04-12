"""
backend/app.py - Differential Testing Backend (WSGI)
-----------------------------------------------------
Modelled directly on HDHunter's python_wsgi application:
    fuzzing_targets/applications/python_wsgi/app.py

Returns a JSON object containing the *parsed* HTTP state tuple so the
fuzzer can compare how Nginx (proxy) vs Gunicorn (backend) interpreted
the same request.

State tuple fields (mirrors HDHunter's comparison model):
    host            : HTTP_HOST header value
    content_length  : CONTENT_LENGTH as seen by backend
    transfer_encoding: HTTP_TRANSFER_ENCODING as seen by backend
    body_content    : raw body text (decoded)
    body_length     : actual consumed body bytes
"""

import json
import time


def application(environ, start_response):
    state = {}

    # ── Parse state tuple (same as HDHunter's python_wsgi/app.py) ────────────
    state["host"]              = environ.get("HTTP_HOST")
    state["method"]            = environ.get("REQUEST_METHOD")
    state["path"]              = environ.get("PATH_INFO")
    state["content_length"]    = environ.get("CONTENT_LENGTH")
    state["transfer_encoding"] = environ.get("HTTP_TRANSFER_ENCODING")

    # Read body — WSGI gives us wsgi.input stream
    try:
        raw_body = environ["wsgi.input"].read()
        state["body_content"] = raw_body.decode("latin-1", errors="replace")
        state["body_length"]  = len(raw_body)
    except Exception as e:
        state["body_content"] = ""
        state["body_length"]  = 0
        state["read_error"]   = str(e)

    # ── Extra desync-relevant headers forwarded by proxy ─────────────────────
    state["x_real_ip"]   = environ.get("HTTP_X_REAL_IP")
    state["x_desync_id"] = environ.get("HTTP_X_DESYNC_ID")   # fuzzer marker
    state["timestamp"]   = time.time()

    # ── Build response headers ────────────────────────────────────────────────
    response_headers = [("Content-Type", "application/json")]
    if state["x_desync_id"]:
        # Echo the desync probe ID back so the fuzzer can pair request ↔ response
        response_headers.append(("X-Desync-Id", state["x_desync_id"]))

    start_response("200 OK", response_headers)
    return [json.dumps(state, indent=2).encode("utf-8")]

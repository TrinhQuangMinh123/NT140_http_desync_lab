"""
app.py - State Tuple Backend (shared across all target environments)
Returns enriched JSON state tuple (HDHunter-inspired: cl_env, body_hash, wsgi_eof).
"""
import json, time, hashlib


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

    response_headers = [("Content-Type", "application/json")]
    if state["x_desync_id"]:
        response_headers.append(("X-Desync-Id", state["x_desync_id"]))
    start_response("200 OK", response_headers)
    return [json.dumps(state, indent=2).encode("utf-8")]

#!/usr/bin/env python3
"""
runner.py - HTTP Desync Differential Fuzzer
--------------------------------------------
HDHunter-inspired differential fuzzing pipeline.

Flow:
    1. Load seeds from seeds_db/
    2. Apply mutation strategies from 03_mutator/
    3. Send mutated payload via Raw TCP to:
           - Proxy endpoint  (Nginx port 8888)
           - Backend direct  (Gunicorn port 9001)
    4. Parse both responses into StateTuples
    5. Run adapted diff_checker rules → flag discrepancies
    6. Save interesting inputs to 05_analyzer/crash_reports/

HDHunter Reference:
    hdhunter-runner/src/run.rs (DiffExecutor, StdPowerMutationalStage)
    hdhunter/src/feedbacks/http_param.rs (is_interesting rules)
"""

import os
import sys
import glob
import json
import re
import socket
import subprocess
import time
import uuid
import random
import argparse
import logging
import hashlib
from datetime import datetime

# ── Resolve import paths ──────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "03_mutator"))

from sequence_level import sequence_splice, sequence_remove, pipeline_encode
from message_level  import (HttpMessage, field_line_duplicate, field_line_remove,
                             field_line_splice, node_token_replace, node_typed_swap,
                             trailer_section_replace)
from byte_level     import (byte_insert, byte_remove, byte_duplicate, byte_splice,
                             obfuscate_transfer_encoding, perturb_content_length)
from advanced_level import obfuscate_whitespace, obfuscate_unicode_encoding, inject_smuggling_prefix
from diff_checker   import StateTuple, compare, print_comparison
from fake_upstream  import FakeUpstream, serve_in_thread

# ── Configuration ─────────────────────────────────────────────────────────────
PROXY_HOST    = "127.0.0.1"
PROXY_PORT    = 8888      # Nginx
BACKEND_HOST  = "127.0.0.1"
BACKEND_PORT  = 9001      # Gunicorn direct

SEEDS_DIR     = os.path.join(ROOT, "01_data_prep", "seeds_db")
RESP_SEEDS_DIR = os.path.join(ROOT, "01_data_prep", "response_seeds_db")
REPORTS_DIR   = os.path.join(ROOT, "05_analyzer", "crash_reports")
SOCKET_TIMEOUT = 5.0
MAX_MUTATIONS  = 3        # mutations per seed
DEFAULT_RANDOM_SEED = 1337
DEFAULT_REPEAT_COUNT = 1
FAKE_UPSTREAM_PORT = 9501
WIRE_TAP_LOG_DEFAULT = "/tmp/wire_tap.log"

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("FuzzRunner")


# ── Network Layer ─────────────────────────────────────────────────────────────

def send_raw(host: str, port: int, payload: bytes) -> tuple:
    """
    Open a raw TCP connection and transmit the payload byte-for-byte.
    Uses raw TCP to bypass client-side HTTP normalization.

    Returns (raw_response_bytes, timed_out, partial_timeout):
        raw_response_bytes : bytes received (possibly empty)
        timed_out          : True if we got NOTHING within the timeout
        partial_timeout    : True if we got SOME bytes but recv() then
                             hit the socket timeout instead of a clean
                             FIN — i.e. the response may be incomplete.
                             Caller should treat such samples as suspect.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)
        s.connect((host, port))
        s.sendall(payload)

        chunks = []
        partial_timeout = False
        clean_close = False
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    clean_close = True
                    break
                chunks.append(chunk)
        except socket.timeout:
            # We received bytes but the peer did not close — could be a
            # keep-alive connection holding open, or a truncated stream.
            # Either way we cannot guarantee the response is complete.
            partial_timeout = len(chunks) > 0
        finally:
            s.close()

        body = b"".join(chunks)
        if not body:
            # No bytes at all: behave like a full timeout.
            return b"", True, False
        return body, False, partial_timeout

    except socket.timeout:
        return b"", True, False
    except ConnectionRefusedError:
        logger.error(f"  [!] Connection refused on {host}:{port} — is the environment up?")
        return b"", True, False
    except Exception:
        return b"", True, False


# ── Seed Loader ───────────────────────────────────────────────────────────────

def load_seeds(seeds_dir: str) -> list:
    """
    Load raw HTTP seeds from the seeds_db directory.
    Reconstructs the original wire-format bytes from the 3-part txt files.
    """
    seeds = []
    for path in sorted(glob.glob(os.path.join(seeds_dir, "seed_*.txt"))):
        with open(path, "rb") as f:
            content = f.read()
        # New Golden Corpus seeds are raw HTTP bytes — use directly.
        # Fallback: try the old 3-section parser format.
        if b"---[START LINE]---" in content:
            raw = _seed_file_to_bytes(content)
        else:
            raw = content
        if raw:
            seeds.append(raw)
    logger.info(f"[*] Loaded {len(seeds)} seeds from {seeds_dir}")
    return seeds


def _seed_file_to_bytes(content: bytes) -> bytes:
    """Parse the 3-section seed file format back into raw HTTP bytes."""
    try:
        start_line = b""
        field_lines = b""
        body = b""

        if b"---[START LINE]---" in content:
            parts = content.split(b"---[START LINE]---")[1]
            parts = parts.split(b"---[FIELD LINES]---")
            start_line = parts[0].strip()
            if len(parts) > 1:
                rest = parts[1].split(b"---[BODY]---")
                field_lines = rest[0].strip()
                if len(rest) > 1:
                    body = rest[1].strip()

        if not start_line:
            return b""

        raw = start_line + b"\r\n" + field_lines + b"\r\n\r\n" + body
        return raw
    except Exception:
        return b""


# ── Mutation Engine ───────────────────────────────────────────────────────────

# All available message-level mutators used by this fuzzer.
# Note: field_line_splice and trailer_section_replace require a donor message
# and exercise paper §4.2.2 + §5.2.2 (trailer section abuse) directly — they
# are dispatched via the donor-aware branch in mutate_payload().
MESSAGE_MUTATORS = [
    field_line_duplicate,
    field_line_remove,
    field_line_splice,           # donor-aware (paper §4.2.2)
    node_token_replace,
    node_typed_swap,
    trailer_section_replace,     # donor-aware (paper §5.2.2)
]

# byte_splice is donor-aware (splices bytes from a second corpus payload).
BYTE_MUTATORS = [
    byte_insert,
    byte_remove,
    byte_duplicate,
    byte_splice,
    obfuscate_transfer_encoding,
    perturb_content_length,
    obfuscate_whitespace,
    obfuscate_unicode_encoding,
    inject_smuggling_prefix,
]


def mutate_payload(payload: bytes, corpus: list) -> tuple:
    """
    Apply a random mutation strategy from the 3 levels.
    Returns (mutated_bytes, mutation_label).
    Select a mutation from the project mutator set.
    """
    level = random.choice(["sequence", "message", "byte"])

    if level == "sequence" and len(corpus) > 1:
        seq = [payload]
        choice = random.choice(["splice", "remove"])
        if choice == "splice":
            seq = sequence_splice(seq, corpus)
            return pipeline_encode(seq), "sequence:splice"
        else:
            seq.append(random.choice(corpus))
            seq = sequence_remove(seq)
            return pipeline_encode(seq), "sequence:remove"

    elif level == "message":
        msg = HttpMessage.from_bytes(payload)
        donor_msg = HttpMessage.from_bytes(random.choice(corpus))
        mutator = random.choice(MESSAGE_MUTATORS)
        if mutator in (field_line_splice, trailer_section_replace):
            result = mutator(msg, donor_msg)
        else:
            result = mutator(msg)
        return result.to_bytes(), f"message:{mutator.__name__}"

    else:  # byte
        mutator = random.choice(BYTE_MUTATORS)
        if mutator == byte_splice:
            return mutator(payload, random.choice(corpus)), "byte:splice"
        return mutator(payload), f"byte:{mutator.__name__}"


# ── X-Desync-Id Injection (paper §4.4.1 — Order tracking) ────────────────────

# Match the start of an HTTP/1.x request line. The lookbehind via lookahead
# in split() lets us keep the request line attached to its segment.
_REQUEST_LINE_RE = re.compile(
    rb"(?=[A-Z]{3,10} \S+ HTTP/1\.[01]\r\n)"
)


def inject_desync_ids(payload: bytes) -> bytes:
    """
    Inject a unique `X-Desync-Id: <uuid>` header into every HTTP request in
    `payload`. For pipelined seeds this produces a per-message UUID so the
    fuzzer can reconstruct the response order (paper §4.4.1).

    Skip messages that already carry the header. Leave malformed payloads
    untouched so byte-mutators can still trigger parser errors.
    """
    if not payload:
        return payload

    segments = _REQUEST_LINE_RE.split(payload)
    out = []
    for seg in segments:
        if not seg:
            continue
        # Skip if it doesn't look like a request OR already has the header
        if b" HTTP/1." not in seg or b"X-Desync-Id:" in seg:
            out.append(seg)
            continue
        # Locate end-of-headers
        sep = seg.find(b"\r\n\r\n")
        if sep < 0:
            out.append(seg)
            continue
        header = (
            b"X-Desync-Id: " + uuid.uuid4().hex.encode() + b"\r\n"
        )
        out.append(seg[:sep + 2] + header + seg[sep + 2:])
    return b"".join(out)


# ── Report Writer ─────────────────────────────────────────────────────────────

def execute_payload(payload: bytes, shm=None):
    """
    Run one payload through proxy and direct backend once.

    Returns (DiffResult-or-None, timed_out_flag, executed_payload). The
    executed_payload is the byte sequence ACTUALLY sent on the wire (which
    includes the per-request X-Desync-Id headers we injected), so it can be
    saved verbatim for faithful replay.

    When `shm` (a WitcherShm) is given, the backend's real per-request coverage
    bitmap + HttpParam 7-tuple are read out-of-band: reset -> send -> read, done
    separately for the proxy-forwarded and the direct request (both hit the same
    single-worker backend, so they must be serialized with a reset between).
    """
    tagged = inject_desync_ids(payload)

    if shm is not None:
        shm.reset()
        proxy_raw,  proxy_to,  proxy_partial  = send_raw(PROXY_HOST, PROXY_PORT, tagged)
        time.sleep(0.02)  # let the backend finish writing the shm
        # snapshot proxy-side shm BEFORE the direct send overwrites it
        p_new, p_fp, p_tot, _ = shm.read_coverage()
        p_cnt, p_cons, p_cl, p_chk = shm.read_state()

        shm.reset()
        direct_raw, direct_to, direct_partial = send_raw(BACKEND_HOST, BACKEND_PORT, tagged)
        time.sleep(0.02)
        d_new, d_fp, d_tot, _ = shm.read_coverage()
        d_cnt, d_cons, d_cl, d_chk = shm.read_state()
    else:
        proxy_raw,  proxy_to,  proxy_partial  = send_raw(PROXY_HOST,   PROXY_PORT,   tagged)
        direct_raw, direct_to, direct_partial = send_raw(BACKEND_HOST, BACKEND_PORT, tagged)

    if proxy_to and direct_to:
        return None, True, tagged

    proxy_state  = StateTuple.from_raw_response(proxy_raw,  proxy_to)
    direct_state = StateTuple.from_raw_response(direct_raw, direct_to)
    proxy_state.partial_timeout  = proxy_partial
    direct_state.partial_timeout = direct_partial

    if shm is not None:
        for st, vals in (
            (proxy_state,  (p_new, p_fp, p_tot, p_cnt, p_cons, p_cl, p_chk)),
            (direct_state, (d_new, d_fp, d_tot, d_cnt, d_cons, d_cl, d_chk)),
        ):
            (st.cov_new_edges, st.cov_fingerprint, st.cov_total_edges,
             st.count_real, st.consumed_real,
             st.content_length_real, st.chunked_real) = vals
            st.cov_fingerprint = st.cov_fingerprint or None
            st.state_source = "httpparam-shm"

    return compare(proxy_state, direct_state), False, tagged


def summarize_repeats(results: list, repeat_attempts: int, skipped_repeats: int) -> dict:
    """Summarize repeat-run stability for one logical test case."""
    discrepancy_runs = [r for r in results if r.is_discrepancy]
    rule_sets = []
    for r in discrepancy_runs:
        rule_sets.append(tuple(sorted(rule["rule"] for rule in r.triggered_rules)))

    unique_rule_sets = sorted(set(rule_sets))
    return {
        "repeat_attempts": repeat_attempts,
        "completed_repeats": len(results),
        "skipped_repeats": skipped_repeats,
        "discrepancy_runs": len(discrepancy_runs),
        "stable_discrepancy": (
            repeat_attempts > 0
            and skipped_repeats == 0
            and len(discrepancy_runs) == repeat_attempts
        ),
        "unique_rule_sets": [list(rule_set) for rule_set in unique_rule_sets],
    }


def save_report(payload: bytes, result, label: str, seed_idx: int, mut_idx: int,
                target_label: str = "", metadata: dict | None = None,
                wire_tap_log: str = "",
                executed_payload: bytes | None = None):
    """Save a discrepancy report to the crash_reports directory.

    `payload`           = the pre-mutation byte sequence (replayable for
                          reproducing the *intent* of the mutation, but
                          missing the per-request UUID injection).
    `executed_payload`  = the EXACT bytes the runner put on the wire
                          (with X-Desync-Id headers). Saved separately so
                          replay can reconstruct the same response order.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    label_prefix = f"{target_label}_" if target_label else ""
    base = os.path.join(REPORTS_DIR, f"discrepancy_{label_prefix}{ts}")

    # Save raw payload that triggered the diff (pre-inject form)
    with open(f"{base}.payload", "wb") as f:
        f.write(payload)
    # Save the exact bytes actually sent (post X-Desync-Id injection) so
    # replay scripts can reproduce identical request boundaries.
    if executed_payload is not None and executed_payload != payload:
        with open(f"{base}.executed.payload", "wb") as f:
            f.write(executed_payload)

    # Save structured report
    report = {
        "target": target_label,
        "timestamp": ts,
        "seed_index": seed_idx,
        "mutation_index": mut_idx,
        "mutation_label": label,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "confidence": getattr(result, "confidence", "high"),
        "diff_notes": getattr(result, "notes", []),
        "triggered_rules": result.triggered_rules,
        "proxy_state": {
            "status":                   result.proxy.status,
            "observed_response_count":  result.proxy.message_count,
            "observed_messages_parsed": result.proxy.message_processed,
            "wsgi_content_length":      result.proxy.content_length,
            "wsgi_transfer_encoding":   result.proxy.transfer_encoding,
            "wsgi_body_length":         result.proxy.body_length,
            "raw_response_length":      result.proxy.consumed_length,
            "response_order":           result.proxy.order,
            "body_hash":                result.proxy.body_hash,
            "wsgi_eof":                 result.proxy.wsgi_eof,
            "cov_new_edges":            result.proxy.cov_new_edges,
            "cov_total_edges":          result.proxy.cov_total_edges,
            "cov_fingerprint":          result.proxy.cov_fingerprint,
            "count_real":               result.proxy.count_real,
            "consumed_real":            result.proxy.consumed_real,
            "content_length_real":      result.proxy.content_length_real,
            "chunked_real":             result.proxy.chunked_real,
            "state_source":             result.proxy.state_source,
            "partial_timeout":          result.proxy.partial_timeout,
        },
        "direct_state": {
            "status":                   result.direct.status,
            "observed_response_count":  result.direct.message_count,
            "observed_messages_parsed": result.direct.message_processed,
            "wsgi_content_length":      result.direct.content_length,
            "wsgi_transfer_encoding":   result.direct.transfer_encoding,
            "wsgi_body_length":         result.direct.body_length,
            "raw_response_length":      result.direct.consumed_length,
            "response_order":           result.direct.order,
            "body_hash":                result.direct.body_hash,
            "wsgi_eof":                 result.direct.wsgi_eof,
            "cov_new_edges":            result.direct.cov_new_edges,
            "cov_total_edges":          result.direct.cov_total_edges,
            "cov_fingerprint":          result.direct.cov_fingerprint,
            "count_real":               result.direct.count_real,
            "consumed_real":            result.direct.consumed_real,
            "content_length_real":      result.direct.content_length_real,
            "chunked_real":             result.direct.chunked_real,
            "state_source":             result.direct.state_source,
            "partial_timeout":          result.direct.partial_timeout,
        },
    }
    if metadata:
        report["repeat_analysis"] = metadata
    if wire_tap_log:
        tap = read_new_wire_tap_entries(wire_tap_log)
        if tap:
            report["wire_tap"] = tap
    with open(f"{base}.json", "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"  [save] Report saved -> {base}.json")


# ── Wire-tap log reading (#4 medium-tier internal state) ─────────────────────

_wire_tap_offset = 0  # remember where we last read so we only attach new lines


def read_new_wire_tap_entries(log_path: str, max_entries: int = 64) -> list:
    """
    Read JSON-lines appended to the wire_tap log since our last call.

    Returns up to `max_entries` most recent entries (each is a dict with
    ts/conn/dir/len/hex). Used to attach proxy→backend wire bytes to a
    discrepancy report, giving us "what proxy actually forwarded" — the
    medium-tier equivalent of paper §4.4.1's parser-internal observation.
    """
    global _wire_tap_offset
    if not log_path or not os.path.exists(log_path):
        return []
    try:
        with open(log_path, "rb") as f:
            f.seek(_wire_tap_offset)
            chunk = f.read()
            _wire_tap_offset = f.tell()
    except OSError:
        return []
    entries = []
    for line in chunk.splitlines():
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line.decode("utf-8", errors="replace")))
        except (json.JSONDecodeError, UnicodeError):
            continue
    return entries[-max_entries:]


# ── Response-side Harness Mode (paper §4.3.2 mode 2) ─────────────────────────

def load_response_seeds(seeds_dir: str) -> list:
    """Load raw HTTP response payloads for response-side fuzzing."""
    seeds = []
    for path in sorted(glob.glob(os.path.join(seeds_dir, "resp_*.txt"))):
        with open(path, "rb") as f:
            seeds.append(f.read())
    logger.info(f"[*] Loaded {len(seeds)} response seeds from {seeds_dir}")
    return seeds


def execute_response_payload(response_payload: bytes,
                             resp_test_path: str = "/resp-test/") -> tuple:
    """
    Drive the response-side harness: start fake_upstream, fire a client
    request at the proxy's /resp-test/ route, capture what the proxy
    relays back. The proxy's RESPONSE parser is the target.

    Returns (client_state_tuple, upstream_request_bytes, timed_out).
    """
    upstream = FakeUpstream(port=FAKE_UPSTREAM_PORT)
    serve_in_thread(upstream, response_payload, timeout=SOCKET_TIMEOUT)
    # Trigger request that proxy will forward to fake_upstream.
    client_req = (
        f"GET {resp_test_path} HTTP/1.1\r\n"
        f"Host: probe\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    proxy_raw, timed_out, proxy_partial = send_raw(PROXY_HOST, PROXY_PORT, client_req)
    # Give the upstream thread a moment to record what it received.
    time.sleep(0.05)
    upstream_request = upstream.last_request()
    if timed_out and not proxy_raw:
        return None, upstream_request, True

    proxy_state  = StateTuple.from_raw_response(proxy_raw, timed_out)
    proxy_state.partial_timeout = proxy_partial
    # For the "direct" side in response mode we compare what the FAKE UPSTREAM
    # SENT (ground truth) against what the CLIENT received via the proxy.
    direct_state = StateTuple.from_raw_response(response_payload, False)
    diff = compare(proxy_state, direct_state)
    return diff, upstream_request, False


# ── Snapshot-like State Reset (paper §4.3, container-restart workaround) ─────

def health_probe(timeout: float = 15.0) -> bool:
    """
    Send a benign GET to both proxy and backend until both return data.
    Returns True if both endpoints are responsive within `timeout` seconds.
    This is our "ready check" — equivalent to paper §4.3.1's snapshot
    readiness probe, but at the network layer.
    """
    probe = b"GET / HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n"
    deadline = time.time() + timeout
    while time.time() < deadline:
        proxy_ok = False
        backend_ok = False
        for host, port, slot in [
            (PROXY_HOST, PROXY_PORT, "proxy"),
            (BACKEND_HOST, BACKEND_PORT, "backend"),
        ]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((host, port))
                s.sendall(probe)
                data = s.recv(64)
                s.close()
                if data.startswith(b"HTTP/"):
                    if slot == "proxy":
                        proxy_ok = True
                    else:
                        backend_ok = True
            except Exception:
                pass
        if proxy_ok and backend_ok:
            return True
        time.sleep(0.5)
    return False


def restart_environment(compose_file: str) -> bool:
    """
    Restart the docker-compose environment to reset HTTP/TCP state between
    fuzzing batches — analogous to paper §4.3's snapshot-restore step.
    Returns True if the environment is healthy after restart.
    """
    if not compose_file or not os.path.exists(compose_file):
        logger.warning(f"  [!] No compose file at {compose_file}, skipping restart")
        return False
    logger.info(f"  [snap] Restarting environment via {compose_file} ...")
    try:
        subprocess.run(
            ["docker", "compose", "-f", compose_file, "restart"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=60,
        )
    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.warning(f"  [!] docker restart failed: {e}")
        return False
    ready = health_probe(timeout=20.0)
    if ready:
        logger.info(f"  [snap] Environment ready.")
    else:
        logger.warning(f"  [!] Environment did NOT become healthy after restart")
    return ready


# ── Main Fuzzing Loop ─────────────────────────────────────────────────────────

def _trace_execution(trace_log: str, seed_idx: int, mut_idx: int, label: str, result):
    """Append one JSONL line per logical case (discrepancy OR same) for B6/B8.

    B8 (coverage blind-spot) needs the cov_fingerprint + real state of ALL cases,
    not just discrepancies, to count "different desync state ∧ identical fingerprint".
    """
    if not trace_log:
        return
    rec = {
        "seed_index": seed_idx,
        "mutation_index": mut_idx,
        "mutation_label": label,
        "is_discrepancy": result.is_discrepancy,
        "rules": sorted(r["rule"] for r in result.triggered_rules),
    }
    for tag, st in (("proxy", result.proxy), ("direct", result.direct)):
        rec[tag] = {
            "cov_fingerprint": st.cov_fingerprint,
            "cov_new_edges": st.cov_new_edges,
            "count_real": st.count_real,
            "consumed_real": st.consumed_real,
            "content_length_real": st.content_length_real,
            "chunked_real": st.chunked_real,
            # legacy wire-derived, for the B6 false-positive audit:
            "wire_count": st.message_count,
            "wire_consumed": st.consumed_length,
        }
    with open(trace_log, "a") as f:
        f.write(json.dumps(rec) + "\n")


def run_fuzzer(seeds: list, num_mutations: int, quiet: bool,
               target_label: str = "", repeat_count: int = 1,
               restart_every: int = 0, compose_file: str = "",
               grow_corpus: bool = True, wire_tap_log: str = "", shm=None,
               trace_log: str = ""):
    """
    Main differential fuzzing loop.
    Main fuzzing loop inspired by HDHunter's differential executor design.

    When `grow_corpus` is True and the backend reports coverage data, any
    mutation that triggers a NEW edge on the backend AND does NOT cause a
    discrepancy is appended to the live corpus (paper §4.2.3 — discrepancy
    inputs are excluded to avoid duplicate findings).
    """
    total   = 0
    executions = 0
    found   = 0
    skipped = 0
    corpus_growth = 0   # how many inputs the coverage feedback added

    logger.info("=" * 70)
    logger.info(f"  HTTP Desync Differential Fuzzer (request-side)")
    logger.info(f"  Target   → {target_label or 'default'}")
    logger.info(f"  Proxy    → {PROXY_HOST}:{PROXY_PORT}")
    logger.info(f"  Backend  → {BACKEND_HOST}:{BACKEND_PORT}")
    logger.info(f"  Seeds    = {len(seeds)}  |  Mutations/seed = {num_mutations}")
    logger.info(f"  Repeats  = {repeat_count} per logical test case")
    logger.info(f"  Oracle: observed-response StateTuple (not parser-internal)")
    logger.info(f"  Coverage feedback: backend-side approximation only "
                f"(paper §4.2.3 uses combined edge maps of BOTH impls)")
    logger.info("=" * 70)

    # Live corpus that grows when coverage feedback says "interesting".
    live_corpus = list(seeds)

    for seed_idx, seed in enumerate(seeds):
        # Generate a batch of mutations for every seed
        variants = [(seed, "original")]
        for m in range(num_mutations):
            try:
                mutated, label = mutate_payload(seed, live_corpus)
                variants.append((mutated, label))
            except Exception:
                pass

        for mut_idx, (payload, label) in enumerate(variants):
            total += 1
            display_label = f"seed {seed_idx+1:02d}  mut {mut_idx:02d}  [{label}]"

            # Snapshot-like reset (paper §4.3): periodically restart the env
            # to guarantee clean TCP/HTTP buffer state. `restart_every=0` disables.
            if restart_every > 0 and total > 1 and (total - 1) % restart_every == 0:
                restart_environment(compose_file)

            repeat_results = []
            repeat_skips = 0
            last_executed = payload  # fallback for saving if all repeats skipped
            for repeat_idx in range(repeat_count):
                executions += 1
                result, skipped_run, executed = execute_payload(payload, shm=shm)
                last_executed = executed
                if skipped_run:
                    repeat_skips += 1
                    continue
                repeat_results.append(result)

            if not repeat_results:
                skipped += 1
                if not quiet:
                    logger.info(f"  [skip]  {display_label}  -- both endpoints timed out")
                continue

            summary = summarize_repeats(repeat_results, repeat_count, repeat_skips)
            result = next((r for r in repeat_results if r.is_discrepancy), repeat_results[0])

            _trace_execution(trace_log, seed_idx, mut_idx, label, result)

            if result.is_discrepancy:
                found += 1
                print_comparison(result, display_label)
                if repeat_count > 1 and not summary["stable_discrepancy"]:
                    logger.info(
                        f"  [unstable] discrepancy reproduced "
                        f"{summary['discrepancy_runs']}/{summary['repeat_attempts']} runs"
                    )
                metadata = {
                    **summary,
                }
                save_report(payload, result, label, seed_idx, mut_idx,
                            target_label, metadata, wire_tap_log=wire_tap_log,
                            executed_payload=last_executed)
            elif not quiet:
                print_comparison(result, display_label)

            # #3 Coverage-directed corpus growth (paper §4.2.3).
            # If the backend reported new edges AND there was no
            # discrepancy, keep this mutation as a future parent.
            if (grow_corpus
                    and not result.is_discrepancy
                    and result.direct.cov_new_edges
                    and result.direct.cov_new_edges > 0
                    and len(live_corpus) < len(seeds) * 4):  # bound growth
                live_corpus.append(payload)
                corpus_growth += 1

    logger.info("\n" + "=" * 70)
    logger.info(f"  [✓] Fuzzing Complete")
    logger.info(f"      Logical test cases : {total}")
    logger.info(f"      Raw executions     : {executions}")
    logger.info(f"      Discrepancies      : {found}")
    logger.info(f"      Skipped cases      : {skipped}")
    logger.info(f"      Corpus growth      : +{corpus_growth} (coverage-directed)")
    logger.info(f"      Reports saved in : {REPORTS_DIR}/")
    logger.info("=" * 70)


# ── Response-side Fuzzing Driver ──────────────────────────────────────────────

def run_fuzzer_response(resp_seeds: list, num_mutations: int, quiet: bool,
                        target_label: str = "", restart_every: int = 0,
                        compose_file: str = "", wire_tap_log: str = ""):
    """
    Response-side fuzzing loop (paper §4.3.2 mode 2).

    For each response seed (+ N mutations):
      1. fake_upstream queues the response bytes.
      2. Fuzzer sends GET /resp-test/ to the proxy.
      3. Proxy contacts fake_upstream, gets the malformed response,
         relays it back to the fuzzer (the client).
      4. Compare what the client received vs the ground-truth bytes
         the upstream sent → any divergence implies the proxy's response
         parser is re-interpreting headers (Response TE.CL, trailer, etc.).
    """
    total = 0
    found = 0
    skipped = 0

    logger.info("=" * 70)
    logger.info(f"  HTTP Desync RESPONSE-side Harness (paper §4.3.2 mode 2)")
    logger.info(f"  Target → {target_label or 'default'}")
    logger.info(f"  Proxy  → {PROXY_HOST}:{PROXY_PORT} (/resp-test/)")
    logger.info(f"  Fake upstream port {FAKE_UPSTREAM_PORT}")
    logger.info(f"  Response seeds = {len(resp_seeds)}  | Mutations/seed = {num_mutations}")
    if restart_every > 0:
        logger.info(f"  Snapshot reset every {restart_every} response tests via {compose_file}")
    logger.info(f"  Scope note: this mode demos proxy response framing/")
    logger.info(f"   sanitization behavior. Detector is the SAME observed-")
    logger.info(f"   response StateTuple as request mode (no JSON body, so")
    logger.info(f"   CL/TE/body_hash signals are coarser than in request mode).")
    logger.info("=" * 70)

    for seed_idx, seed in enumerate(resp_seeds):
        variants = [(seed, "original")]
        for _ in range(num_mutations):
            try:
                # Reuse the byte-level mutators on the response bytes.
                mutator = random.choice(BYTE_MUTATORS)
                if mutator == byte_splice:
                    mutated = mutator(seed, random.choice(resp_seeds))
                else:
                    mutated = mutator(seed)
                variants.append((mutated, f"byte:{mutator.__name__}"))
            except Exception:
                pass

        for mut_idx, (payload, label) in enumerate(variants):
            total += 1
            display_label = f"resp {seed_idx+1:02d}  mut {mut_idx:02d}  [{label}]"

            # Keep response-side isolation aligned with request-side:
            # restart before each logical test after the first one.
            if restart_every > 0 and total > 1 and (total - 1) % restart_every == 0:
                restart_environment(compose_file)

            try:
                diff, upstream_req, timed_out = execute_response_payload(payload)
            except OSError as e:
                logger.warning(f"  [!] {display_label}: {e}")
                skipped += 1
                continue
            if timed_out or diff is None:
                skipped += 1
                if not quiet:
                    logger.info(f"  [skip] {display_label} -- no proxy response")
                continue

            if diff.is_discrepancy:
                found += 1
                print_comparison(diff, display_label)
                # Save with a response-side tag so triage can separate.
                rs_label = f"{target_label}_response" if target_label else "response"
                metadata = {
                    "mode": "response",
                    "upstream_received_bytes": len(upstream_req),
                    # Response-side runs do not inject X-Desync-Id (no
                    # client request to mutate), so executed == payload.
                }
                save_report(payload, diff, label, seed_idx, mut_idx, rs_label,
                            metadata, wire_tap_log=wire_tap_log,
                            executed_payload=payload)
            elif not quiet:
                print_comparison(diff, display_label)

    logger.info("\n" + "=" * 70)
    logger.info(f"  [✓] Response-side Fuzzing Complete")
    logger.info(f"      Logical test cases : {total}")
    logger.info(f"      Discrepancies      : {found}")
    logger.info(f"      Skipped cases      : {skipped}")
    logger.info("=" * 70)


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    global PROXY_PORT, BACKEND_PORT, REPORTS_DIR

    parser = argparse.ArgumentParser(
        description="HTTP Desync Differential Fuzzer (HDHunter-inspired)")
    parser.add_argument("--seeds",        default=SEEDS_DIR,
                        help="Path to seeds directory")
    parser.add_argument("--mutations",    type=int, default=MAX_MUTATIONS,
                        help="Number of mutations per seed (default: 3)")
    parser.add_argument("--proxy-port",   type=int, default=PROXY_PORT,
                        help="Proxy port (default: 8888)")
    parser.add_argument("--backend-port", type=int, default=BACKEND_PORT,
                        help="Backend direct port (default: 9001)")
    parser.add_argument("--quiet", action="store_true",
                        help="Only print discrepancies, skip matching cases")
    parser.add_argument("--label",        default="",
                        help="Target environment label (e.g. nginx_gunicorn) for report tagging")
    parser.add_argument("--random-seed", type=int, default=DEFAULT_RANDOM_SEED,
                        help=f"Seed for deterministic mutation selection (default: {DEFAULT_RANDOM_SEED})")
    parser.add_argument("--repeat", type=int, default=DEFAULT_REPEAT_COUNT,
                        help="Repeat each logical test case N times to measure stability (default: 1)")
    parser.add_argument("--restart-every", type=int, default=0,
                        help="Restart docker-compose env every N test cases (snapshot-like reset, default: 0 = disabled)")
    parser.add_argument("--compose-file", default="",
                        help="Path to docker-compose.yml for --restart-every; required if restart-every > 0")
    parser.add_argument("--mode", choices=["request", "response"], default="request",
                        help="Test direction: 'request' (default) fuzzes proxy→backend request parsing; "
                             "'response' fuzzes proxy response parsing via fake upstream (paper §4.3.2 mode 2)")
    parser.add_argument("--response-seeds", default=RESP_SEEDS_DIR,
                        help="Response seed directory (used when --mode response)")
    parser.add_argument("--wire-tap-log", default="",
                        help="Path to wire_tap.py JSON log; if set, recent entries are attached to reports")
    parser.add_argument("--witcher", action="store_true",
                        help="Paper-faithful mode: bring up the Witcher backend (gunicorn under "
                             "patched CPython), create SysV shm, and read real per-request coverage "
                             "(bitmap+fingerprint) + HttpParam 7-tuple (count_real/consumed_real) out-of-band.")
    _ng = os.path.join(ROOT, "02_targets", "nginx_gunicorn")
    parser.add_argument("--witcher-compose-base", default=os.path.join(_ng, "docker-compose.yml"),
                        help="Base compose file for --witcher")
    parser.add_argument("--witcher-compose-override", default=os.path.join(_ng, "docker-compose.witcher.yml"),
                        help="Witcher override compose file for --witcher")
    parser.add_argument("--witcher-no-build", action="store_true",
                        help="Skip --build when bringing up the Witcher backend")
    parser.add_argument("--reports-dir", default="",
                        help="Override directory for discrepancy reports (e.g. crash_reports_cov_<id>)")
    parser.add_argument("--trace-log", default="",
                        help="Append one JSONL line per logical case (cov_fingerprint + real state) for B6/B8 analysis")
    args = parser.parse_args()

    if args.reports_dir:
        REPORTS_DIR = (args.reports_dir if os.path.isabs(args.reports_dir)
                       else os.path.join(ROOT, "05_analyzer", args.reports_dir))
        os.makedirs(REPORTS_DIR, exist_ok=True)

    PROXY_PORT   = args.proxy_port
    BACKEND_PORT = args.backend_port
    random.seed(args.random_seed)

    if args.repeat < 1:
        logger.error("[!] --repeat must be >= 1")
        sys.exit(1)

    if args.restart_every > 0 and not args.compose_file:
        logger.error("[!] --restart-every requires --compose-file <path>")
        sys.exit(1)

    seeds = load_seeds(args.seeds)
    if not seeds:
        logger.error("[!] No seeds found. Run 01_data_prep/collector.py first.")
        sys.exit(1)

    logger.info(f"[*] Random seed = {args.random_seed}")
    if args.restart_every > 0:
        logger.info(f"[*] Snapshot reset: every {args.restart_every} tests via {args.compose_file}")

    if args.mode == "response":
        resp_seeds = load_response_seeds(args.response_seeds)
        if not resp_seeds:
            logger.error("[!] No response seeds found in %s", args.response_seeds)
            sys.exit(1)
        run_fuzzer_response(resp_seeds, args.mutations, args.quiet, args.label,
                            restart_every=args.restart_every,
                            compose_file=args.compose_file,
                            wire_tap_log=args.wire_tap_log)
    elif args.witcher:
        from hdhunter_shm import WitcherBackend
        if not health_probe(timeout=1.0):
            logger.info("[*] Witcher mode: bringing up backend under patched CPython ...")
        with WitcherBackend(args.witcher_compose_base, args.witcher_compose_override,
                            build=not args.witcher_no_build, logger=logger.info) as shm:
            if not health_probe(timeout=30.0):
                logger.error("[!] Witcher backend did not become healthy")
                sys.exit(1)
            logger.info("[*] Witcher backend healthy — coverage + HttpParam shm live")
            run_fuzzer(seeds, args.mutations, args.quiet, args.label, args.repeat,
                       restart_every=args.restart_every,
                       compose_file=args.compose_file,
                       wire_tap_log=args.wire_tap_log, shm=shm,
                       trace_log=args.trace_log)
    else:
        run_fuzzer(seeds, args.mutations, args.quiet, args.label, args.repeat,
                   restart_every=args.restart_every,
                   compose_file=args.compose_file,
                   wire_tap_log=args.wire_tap_log)


if __name__ == "__main__":
    main()

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

# ── Configuration ─────────────────────────────────────────────────────────────
PROXY_HOST    = "127.0.0.1"
PROXY_PORT    = 8888      # Nginx
BACKEND_HOST  = "127.0.0.1"
BACKEND_PORT  = 9001      # Gunicorn direct

SEEDS_DIR     = os.path.join(ROOT, "01_data_prep", "seeds_db")
REPORTS_DIR   = os.path.join(ROOT, "05_analyzer", "crash_reports")
SOCKET_TIMEOUT = 5.0
MAX_MUTATIONS  = 3        # mutations per seed
DEFAULT_RANDOM_SEED = 1337
DEFAULT_REPEAT_COUNT = 1

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("FuzzRunner")


# ── Network Layer ─────────────────────────────────────────────────────────────

def send_raw(host: str, port: int, payload: bytes) -> tuple:
    """
    Open a raw TCP connection and transmit the payload byte-for-byte.
    Returns (raw_response_bytes, timed_out).
    Uses raw TCP to bypass client-side HTTP normalization.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)
        s.connect((host, port))
        s.sendall(payload)

        chunks = []
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        finally:
            s.close()
        return b"".join(chunks), False

    except socket.timeout:
        return b"", True
    except ConnectionRefusedError:
        logger.error(f"  [!] Connection refused on {host}:{port} — is the environment up?")
        return b"", True
    except Exception as e:
        return b"", True


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
MESSAGE_MUTATORS = [
    field_line_duplicate,
    field_line_remove,
    node_token_replace,
    node_typed_swap,
]

BYTE_MUTATORS = [
    byte_insert,
    byte_remove,
    byte_duplicate,
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

def execute_payload(payload: bytes):
    """Run one payload through proxy and direct backend once."""
    tagged = inject_desync_ids(payload)
    proxy_raw,  proxy_to  = send_raw(PROXY_HOST,   PROXY_PORT,   tagged)
    direct_raw, direct_to = send_raw(BACKEND_HOST, BACKEND_PORT, tagged)

    if proxy_to and direct_to:
        return None, True

    proxy_state  = StateTuple.from_raw_response(proxy_raw,  proxy_to)
    direct_state = StateTuple.from_raw_response(direct_raw, direct_to)
    return compare(proxy_state, direct_state), False


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
                target_label: str = "", metadata: dict | None = None):
    """Save a discrepancy report to the crash_reports directory."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    label_prefix = f"{target_label}_" if target_label else ""
    base = os.path.join(REPORTS_DIR, f"discrepancy_{label_prefix}{ts}")

    # Save raw payload that triggered the diff
    with open(f"{base}.payload", "wb") as f:
        f.write(payload)

    # Save structured report
    report = {
        "target": target_label,
        "timestamp": ts,
        "seed_index": seed_idx,
        "mutation_index": mut_idx,
        "mutation_label": label,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "triggered_rules": result.triggered_rules,
        "proxy_state": {
            "status":            result.proxy.status,
            "message_count":     result.proxy.message_count,
            "message_processed": result.proxy.message_processed,
            "content_length":    result.proxy.content_length,
            "transfer_encoding": result.proxy.transfer_encoding,
            "body_length":       result.proxy.body_length,
            "consumed_length":   result.proxy.consumed_length,
            "order":             result.proxy.order,
            "body_hash":         result.proxy.body_hash,
            "wsgi_eof":          result.proxy.wsgi_eof,
        },
        "direct_state": {
            "status":            result.direct.status,
            "message_count":     result.direct.message_count,
            "message_processed": result.direct.message_processed,
            "content_length":    result.direct.content_length,
            "transfer_encoding": result.direct.transfer_encoding,
            "body_length":       result.direct.body_length,
            "consumed_length":   result.direct.consumed_length,
            "order":             result.direct.order,
            "body_hash":         result.direct.body_hash,
            "wsgi_eof":          result.direct.wsgi_eof,
        },
    }
    if metadata:
        report["repeat_analysis"] = metadata
    with open(f"{base}.json", "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"  [save] Report saved -> {base}.json")


# ── Main Fuzzing Loop ─────────────────────────────────────────────────────────

def run_fuzzer(seeds: list, num_mutations: int, quiet: bool,
               target_label: str = "", repeat_count: int = 1):
    """
    Main differential fuzzing loop.
    Main fuzzing loop inspired by HDHunter's differential executor design.
    """
    total   = 0
    executions = 0
    found   = 0
    skipped = 0

    logger.info("=" * 70)
    logger.info(f"  HTTP Desync Differential Fuzzer")
    logger.info(f"  Target   → {target_label or 'default'}")
    logger.info(f"  Proxy    → {PROXY_HOST}:{PROXY_PORT}")
    logger.info(f"  Backend  → {BACKEND_HOST}:{BACKEND_PORT}")
    logger.info(f"  Seeds    = {len(seeds)}  |  Mutations/seed = {num_mutations}")
    logger.info(f"  Repeats  = {repeat_count} per logical test case")
    logger.info("=" * 70)

    for seed_idx, seed in enumerate(seeds):
        # Generate a batch of mutations for every seed
        variants = [(seed, "original")]
        for m in range(num_mutations):
            try:
                mutated, label = mutate_payload(seed, seeds)
                variants.append((mutated, label))
            except Exception:
                pass

        for mut_idx, (payload, label) in enumerate(variants):
            total += 1
            display_label = f"seed {seed_idx+1:02d}  mut {mut_idx:02d}  [{label}]"

            repeat_results = []
            repeat_skips = 0
            for repeat_idx in range(repeat_count):
                executions += 1
                result, skipped_run = execute_payload(payload)
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
                save_report(payload, result, label, seed_idx, mut_idx, target_label, metadata)
            elif not quiet:
                print_comparison(result, display_label)

    logger.info("\n" + "=" * 70)
    logger.info(f"  [✓] Fuzzing Complete")
    logger.info(f"      Logical test cases : {total}")
    logger.info(f"      Raw executions     : {executions}")
    logger.info(f"      Discrepancies      : {found}")
    logger.info(f"      Skipped cases      : {skipped}")
    logger.info(f"      Reports saved in : {REPORTS_DIR}/")
    logger.info("=" * 70)


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    global PROXY_PORT, BACKEND_PORT

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
    args = parser.parse_args()

    PROXY_PORT   = args.proxy_port
    BACKEND_PORT = args.backend_port
    random.seed(args.random_seed)

    if args.repeat < 1:
        logger.error("[!] --repeat must be >= 1")
        sys.exit(1)

    seeds = load_seeds(args.seeds)
    if not seeds:
        logger.error("[!] No seeds found. Run 01_data_prep/collector.py first.")
        sys.exit(1)

    logger.info(f"[*] Random seed = {args.random_seed}")
    run_fuzzer(seeds, args.mutations, args.quiet, args.label, args.repeat)


if __name__ == "__main__":
    main()

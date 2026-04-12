#!/usr/bin/env python3
"""
monitor.py - Environment Monitor & Snapshot Controller
-------------------------------------------------------
Replaces HDHunter's Vagrant/QEMU snapshot mechanism with a lightweight
Docker-based equivalent:

  HDHunter (Vagrant/QEMU):
    - Takes a VM snapshot before fuzzing
    - Reverts to snapshot after each test case (clean-state guarantee)

  Our Docker equivalent:
    - Checks container health (liveness probe)
    - Restarts containers to restore clean state (equivalent of snapshot revert)
    - Saves log snapshots for post-analysis

Usage:
    python3 monitor.py --action health
    python3 monitor.py --action snapshot
    python3 monitor.py --action restore
    python3 monitor.py --action logs
"""

import subprocess
import argparse
import time
import json
import os
import sys
from datetime import datetime

# Container names must match docker-compose.yml
PROXY_CONTAINER   = "desync_proxy"
BACKEND_CONTAINER = "desync_backend"

PROXY_URL   = "http://localhost:8080"
BACKEND_URL = "http://localhost:9001"

LOG_DIR = "snapshots"


def _run(cmd: list) -> tuple:
    """Run a shell command and return (stdout, returncode)."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip(), result.returncode


def check_health() -> dict:
    """
    Liveness probe: verify both containers are running and responding.
    Equivalent to HDHunter checking target is alive before sending fuzz input.
    """
    status = {}

    for name in [PROXY_CONTAINER, BACKEND_CONTAINER]:
        out, rc = _run(["docker", "inspect", "--format", "{{.State.Status}}", name])
        status[name] = {"docker_state": out, "healthy": (out == "running")}

    # HTTP-level probe via curl (avoids needing requests lib)
    for label, url in [("proxy", PROXY_URL), ("backend", BACKEND_URL)]:
        _, rc = _run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "2", url])
        status[label + "_http"] = "reachable" if rc == 0 else "unreachable"

    return status


def snapshot_logs(tag: str = "") -> str:
    """
    Capture current container logs as a 'snapshot' (poor-man's QEMU snapshot).
    Saves proxy + backend logs timestamped for differential forensics.
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    label = f"{ts}_{tag}" if tag else ts

    for name in [PROXY_CONTAINER, BACKEND_CONTAINER]:
        log_path = os.path.join(LOG_DIR, f"{name}_{label}.log")
        out, _ = _run(["docker", "logs", "--timestamps", name])
        with open(log_path, "w") as f:
            f.write(out)
        print(f"[snapshot] Saved {name} logs → {log_path}")

    return label


def restore_clean_state() -> bool:
    """
    Restores a clean environment by restarting both containers.
    
    Mirrors: HDHunter's QEMU snapshot revert after each fuzz iteration.
    Docker restart is faster (~1s) and sufficient since the containers 
    are stateless — no test data persists between restarts.
    """
    print("[restore] Reverting to clean state (Docker restart)...")
    for name in [PROXY_CONTAINER, BACKEND_CONTAINER]:
        _, rc = _run(["docker", "restart", name])
        if rc == 0:
            print(f"  [ok] {name} restarted successfully")
        else:
            print(f"  [err] Failed to restart {name}")
            return False

    # Wait for containers to become healthy before signalling ready
    time.sleep(2)
    health = check_health()
    all_healthy = all(v.get("healthy", False) for k, v in health.items() if isinstance(v, dict))
    print(f"[restore] Health check: {'PASS ✓' if all_healthy else 'FAIL ✗'}")
    return all_healthy


def start_environment():
    """Bring up the full environment using docker-compose."""
    print("[start] Starting docker-compose environment...")
    _, rc = _run(["docker", "compose", "up", "-d", "--build"])
    if rc == 0:
        print("[start] Environment is up. Waiting for services to initialise...")
        time.sleep(3)
        status = check_health()
        print(json.dumps(status, indent=2))
    else:
        print("[start] ERROR: docker-compose failed. Is Docker running?")
        sys.exit(1)


def stop_environment():
    """Tear down all containers."""
    print("[stop] Stopping docker-compose environment...")
    _run(["docker", "compose", "down"])


def main():
    parser = argparse.ArgumentParser(description="Desync Environment Monitor & Snapshot Controller")
    parser.add_argument("--action", choices=["health", "snapshot", "restore", "start", "stop", "logs"],
                        required=True, help="Action to perform")
    parser.add_argument("--tag", default="", help="Optional label for snapshot files")
    args = parser.parse_args()

    if args.action == "health":
        status = check_health()
        print(json.dumps(status, indent=2))

    elif args.action == "snapshot":
        label = snapshot_logs(args.tag)
        print(f"[done] Snapshot saved under label '{label}'")

    elif args.action == "restore":
        ok = restore_clean_state()
        sys.exit(0 if ok else 1)

    elif args.action == "start":
        start_environment()

    elif args.action == "stop":
        stop_environment()

    elif args.action == "logs":
        for name in [PROXY_CONTAINER, BACKEND_CONTAINER]:
            out, _ = _run(["docker", "logs", "--tail", "50", name])
            print(f"\n{'='*60}")
            print(f"  Container: {name}")
            print(f"{'='*60}")
            print(out)


if __name__ == "__main__":
    main()

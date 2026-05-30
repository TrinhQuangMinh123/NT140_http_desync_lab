#!/usr/bin/env python3
"""hdhunter_shm.py — runner-side SysV shm manager for the Witcher backend (B3 + B4b).

Out-of-band instrumentation reader. The runner (host) OWNS three SysV shared-memory
segments and hands their ids to the Witcher backend via env vars; the backend attaches
them (coverage written by the patched CPython interpreter, internal-state written by the
patched gunicorn parser via backend/hdhunter.py). Because the backend runs in a container
with `ipc: host`, a host-created shm id is attachable inside it — provided the segment is
world-accessible (0666), since the container's user is namespace-remapped and cannot
attach a 0600 segment owned by the host uid.

Three segments (mirrors HDHunter / Witcher `ceval.c`):
  __AFL_SHM        : AFL edge bitmap, MAPSIZE bytes (one bucket per edge hash).
  __EXECUTION_PATH : 8 bytes, Witcher's rolling edge-hash. MUST exist or Witcher
                     dereferences a NULL `execution_path`/`visited_edges` and segfaults.
  __HTTP_PARAM     : 328-byte HttpParam 7-tuple (Count/Consumed/...).

Per request the runner: reset() -> send -> read_coverage()/read_state(). Zeroing the
bitmap before each request isolates that request's edges (replaces Nyx snapshot-reset, R3).
"""

import os
import ctypes
import hashlib
import subprocess
import time
from ctypes import c_int, c_int8, c_int16, c_int32, c_int64, c_void_p, c_size_t

MAPSIZE = 65536  # AFL bitmap size (must match Witcher MAPSIZE)

# ── SysV shm syscall constants ───────────────────────────────────────────────
IPC_PRIVATE = 0
IPC_CREAT = 0o1000
IPC_RMID = 0
SHM_PERM = 0o666  # world-rw: container user is namespace-remapped (see module docstring)

_N = 10


class HttpParam(ctypes.Structure):
    _fields_ = [
        ("content_length", c_int64 * _N),
        ("chunked_encoding", c_int8 * _N),
        ("consumed_length", c_int64 * _N),
        ("body_length", c_int64 * _N),
        ("message_count", c_int32),
        ("message_processed", c_int8),
        ("status", c_int16 * _N),
        ("order", c_int32 * _N),
    ]


assert ctypes.sizeof(HttpParam) == 328, ctypes.sizeof(HttpParam)

_libc = ctypes.CDLL(None, use_errno=True)
_libc.shmget.restype = c_int
_libc.shmget.argtypes = [c_int, c_size_t, c_int]
_libc.shmat.restype = c_void_p
_libc.shmat.argtypes = [c_int, c_void_p, c_int]
_libc.shmdt.argtypes = [c_void_p]
_libc.shmctl.argtypes = [c_int, c_int, c_void_p]


def _shmget(size):
    sid = _libc.shmget(IPC_PRIVATE, size, IPC_CREAT | SHM_PERM)
    if sid == -1:
        e = ctypes.get_errno()
        raise OSError(e, "shmget(%d): %s" % (size, os.strerror(e)))
    return sid


def _shmat(sid):
    addr = _libc.shmat(sid, None, 0)
    if addr in (None, 0) or addr == c_void_p(-1).value:
        e = ctypes.get_errno()
        raise OSError(e, "shmat(%d): %s" % (sid, os.strerror(e)))
    return addr


class WitcherShm:
    """Owns the 3 SysV segments and reads coverage + internal-state out-of-band."""

    def __init__(self):
        self.afl_id = self.exec_id = self.param_id = None
        self.afl_addr = self.exec_addr = self.param_addr = None
        self.param = None
        self.seen_edges = set()  # run-wide accumulator for cov_new_edges

    def create(self):
        self.afl_id = _shmget(MAPSIZE)
        self.exec_id = _shmget(8)
        self.param_id = _shmget(ctypes.sizeof(HttpParam))
        self.afl_addr = _shmat(self.afl_id)
        self.exec_addr = _shmat(self.exec_id)
        self.param_addr = _shmat(self.param_id)
        self.param = HttpParam.from_address(self.param_addr)
        self.reset()
        return self.env()

    def env(self):
        """Env mapping the backend container needs (passed through by compose)."""
        return {
            "__AFL_SHM": str(self.afl_id),
            "__EXECUTION_PATH": str(self.exec_id),
            "__HTTP_PARAM": str(self.param_id),
        }

    def reset(self):
        """Zero all segments + clear the 7-tuple. Call before every request (R3)."""
        ctypes.memset(self.afl_addr, 0, MAPSIZE)
        ctypes.memset(self.exec_addr, 0, 8)
        ctypes.memset(self.param_addr, 0, ctypes.sizeof(HttpParam))
        # HttpParam.clear() semantics: -1 sentinels for length fields.
        for i in range(_N):
            self.param.content_length[i] = -1
            self.param.consumed_length[i] = -1
            self.param.body_length[i] = -1
        # chunked/status/order/count/processed already zeroed by memset.

    def read_coverage(self):
        """Return (cov_new_edges, cov_fingerprint, cov_total_edges, touched_count).

        touched = bitmap buckets nonzero for THIS request (bitmap was zeroed before).
        cov_new_edges  = buckets never seen before this run.
        cov_fingerprint= sha256 over the sorted touched bucket ids (D2/R9): lets B8 ask
                         "different desync state but identical coverage fingerprint?".
        """
        raw = ctypes.string_at(self.afl_addr, MAPSIZE)
        touched = [i for i, b in enumerate(raw) if b]
        if not touched:
            # No instrumented edges hit (e.g. parser-reject before any included frame).
            return 0, "", len(self.seen_edges), 0
        new_edges = sum(1 for i in touched if i not in self.seen_edges)
        self.seen_edges.update(touched)
        fp_src = b",".join(b"%d" % i for i in touched)  # touched is already sorted
        fingerprint = hashlib.sha256(fp_src).hexdigest()
        return new_edges, fingerprint, len(self.seen_edges), len(touched)

    def read_state(self):
        """Return (count_real, consumed_real, content_length_real, chunked_real).

        count_real = number of messages the parser fully framed. The rt rolls
        message_count forward on the first write of the NEXT message, so the
        in-flight (marked-but-not-rolled) message is message_processed.
        """
        p = self.param
        count_real = p.message_count + (1 if p.message_processed else 0)
        n = max(0, min(count_real, _N))
        consumed_real = [p.consumed_length[i] for i in range(n)]
        content_length_real = [p.content_length[i] for i in range(n)]
        chunked_real = [bool(p.chunked_encoding[i]) for i in range(n)]
        return count_real, consumed_real, content_length_real, chunked_real

    def cleanup(self):
        for addr in (self.afl_addr, self.exec_addr, self.param_addr):
            if addr:
                try:
                    _libc.shmdt(addr)
                except Exception:
                    pass
        for sid in (self.afl_id, self.exec_id, self.param_id):
            if sid is not None:
                try:
                    _libc.shmctl(sid, IPC_RMID, None)
                except Exception:
                    pass
        self.afl_addr = self.exec_addr = self.param_addr = None


class WitcherBackend:
    """Context manager: create shm, bring up the Witcher compose with the ids, tear down.

    Usage:
        with WitcherBackend(base, override) as shm:
            ... fuzz, using shm.reset()/read_coverage()/read_state() ...
    """

    def __init__(self, compose_base, compose_override, build=True,
                 services=("backend", "proxy"), project_dir=None, logger=None):
        self.compose_base = compose_base
        self.compose_override = compose_override
        self.build = build
        self.services = list(services)
        self.project_dir = project_dir or os.path.dirname(compose_base)
        self.shm = WitcherShm()
        self.log = logger or (lambda m: None)

    def _compose(self, *args):
        cmd = ["docker", "compose", "-f", self.compose_base,
               "-f", self.compose_override, *args]
        return subprocess.run(cmd, cwd=self.project_dir, env={**os.environ, **self.shm.env()},
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def __enter__(self):
        env = self.shm.create()
        self.log("[witcher] shm created: %s" % env)
        args = ["up", "-d"]
        if self.build:
            args.append("--build")
        args += self.services
        r = self._compose(*args)
        if r.returncode != 0:
            self.shm.cleanup()
            raise RuntimeError("docker compose up failed:\n%s" % r.stdout)
        self.log("[witcher] backend up (ipc:host, shm ids injected)")
        return self.shm

    def __exit__(self, *exc):
        try:
            self._compose("down")
            self.log("[witcher] compose down")
        finally:
            self.shm.cleanup()
            self.log("[witcher] shm cleaned up")
        return False

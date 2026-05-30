"""hdhunter.py — pure-Python internal-state shim (option (ii), no Rust).

Drop-in replacement for fuzzing_targets/runtime/python/hdhunter.py. Instead of
loading the Rust `libhdhunter_rt_no_edge.so` (which would need cargo + the libafl
workspace and couples us to libafl's shm encoding), this reimplements the
`HttpParam` 7-tuple + the 5 instrumentation calls in pure Python, writing into a
SysV shared-memory segment via ctypes -> libc (shmget/shmat). No external
package (no sysv_ipc), works on the Witcher CPython 3.7.9 interpreter.

Contract with the fuzzer runner (host side):
  * The runner creates a SysV shm segment of >= sizeof(HttpParam) bytes and
    exports its **id** in env var `__HTTP_PARAM` before the backend starts.
  * Backend + runner share the IPC namespace (`ipc: host` in docker-compose),
    so a host-created shm id is attachable inside the container.
  * The runner calls clear() (or zeroes the segment) before each request; the
    backend's parser patches call the set_*/inc_*/mark_* functions during parse;
    the runner reads the struct back after the request -> count_real, consumed_real[].

If `__HTTP_PARAM` is unset or attach fails, every call is a silent no-op so the
backend still runs standalone (e.g. plain `gunicorn app:application`).

Struct layout mirrors hdhunter::observers::HttpParam (#[repr(C)], 328 bytes):
    content_length   [i64;10]
    chunked_encoding [i8;10]
    consumed_length  [i64;10]
    body_length      [i64;10]
    message_count    i32
    message_processed i8
    status           [i16;10]
    order            [i32;10]
"""

import os
import ctypes
from ctypes import c_int, c_int8, c_int16, c_int32, c_int64, c_void_p, c_size_t

# ── Mode bitmask (mirrors hdhunter::mode::Mode) ──────────────────────────────
MODE_REQUEST = 1
MODE_RESPONSE = 2
MODE_SCGI = 4
MODE_FASTCGI = 8
MODE_AJP = 16
MODE_UWSGI = 32

_MODE_NAMES = {
    "request": MODE_REQUEST, "response": MODE_RESPONSE, "scgi": MODE_SCGI,
    "fastcgi": MODE_FASTCGI, "ajp": MODE_AJP, "uwsgi": MODE_UWSGI,
}

_N = 10  # array arity in HttpParam


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

    def clear(self):
        for i in range(_N):
            self.content_length[i] = -1
            self.chunked_encoding[i] = 0
            self.consumed_length[i] = -1
            self.body_length[i] = -1
            self.status[i] = 0
            self.order[i] = 0
        self.message_count = 0
        self.message_processed = 0


assert ctypes.sizeof(HttpParam) == 328, ctypes.sizeof(HttpParam)

# ── libc SysV shm bindings (shmat/shmdt; shmget/shmctl only needed runner-side) ─
_libc = ctypes.CDLL(None, use_errno=True)
_libc.shmat.restype = c_void_p
_libc.shmat.argtypes = [c_int, c_void_p, c_int]
_libc.shmdt.argtypes = [c_void_p]

# ── module state ─────────────────────────────────────────────────────────────
__http_param = None   # HttpParam mapped over shm, or None in no-op mode
_MODE = MODE_REQUEST


def _mode_from_env():
    val = os.environ.get("HDHUNTER_MODE", "request").strip().lower()
    return _MODE_NAMES.get(val, MODE_REQUEST)


def hdhunter_init():
    """Attach to the runner-provided SysV shm (env `__HTTP_PARAM` = shm id)."""
    global __http_param, _MODE
    _MODE = _mode_from_env()
    raw = os.environ.get("__HTTP_PARAM")
    if not raw:
        __http_param = None  # no-op mode (standalone backend)
        return
    shmid = int(raw)
    addr = _libc.shmat(shmid, None, 0)
    if addr in (None, 0) or addr == c_void_p(-1).value:
        err = ctypes.get_errno()
        __http_param = None
        raise OSError(err, "hdhunter: shmat(%d) failed: %s" % (shmid, os.strerror(err)))
    __http_param = HttpParam.from_address(addr)


def hdhunter_clear():
    """Reset the 7-tuple. Runner normally does this per request; exposed for tests."""
    if __http_param is not None:
        __http_param.clear()


def _advance_message_if_processed(p):
    # Mirrors the rt: the first param-write after a completed message rolls over
    # to the next slot.
    if p.message_processed == 1:
        p.message_count += 1
        p.message_processed = 0


def hdhunter_set_content_length(length, mode=MODE_REQUEST):
    p = __http_param
    if p is None or (mode & _MODE) == 0:
        return
    _advance_message_if_processed(p)
    if p.message_count >= _N:
        return
    p.content_length[p.message_count] = length


def hdhunter_set_chunked_encoding(chunked, mode=MODE_REQUEST):
    p = __http_param
    if p is None or (mode & _MODE) == 0:
        return
    _advance_message_if_processed(p)
    if p.message_count >= _N:
        return
    p.chunked_encoding[p.message_count] = chunked


def hdhunter_inc_consumed_length(length, mode=MODE_REQUEST):
    p = __http_param
    if p is None or (mode & _MODE) == 0:
        return
    _advance_message_if_processed(p)
    if p.message_count >= _N:
        return
    i = p.message_count
    if p.consumed_length[i] == -1:
        p.consumed_length[i] = 0
    p.consumed_length[i] += length


def hdhunter_inc_body_length(length, mode=MODE_REQUEST):
    p = __http_param
    if p is None or (mode & _MODE) == 0:
        return
    _advance_message_if_processed(p)
    if p.message_count >= _N:
        return
    i = p.message_count
    if p.body_length[i] == -1:
        p.body_length[i] = 0
    p.body_length[i] += length


def hdhunter_mark_message_processed(mode=MODE_REQUEST):
    p = __http_param
    if p is None or (mode & _MODE) == 0:
        return
    p.message_processed = 1

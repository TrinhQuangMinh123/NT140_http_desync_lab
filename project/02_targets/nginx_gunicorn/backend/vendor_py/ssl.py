"""Minimal `ssl` stub for the Witcher-python (CPython 3.7.9) interpreter.

The patched Witcher interpreter is built WITHOUT the `_ssl` C extension, so the
real stdlib `ssl` module fails to import. gunicorn imports `ssl` unconditionally
(gunicorn/config.py) and references a handful of module-level constants when
building its default config. We never serve HTTPS (the backend is plain HTTP
behind nginx), so the TLS code paths (`wrap_socket`, real `SSLError`) are never
exercised — only the import and the default constants matter.

This file lives in `vendor_py/`, which is first on PYTHONPATH, so it shadows the
broken stdlib `ssl`. If we ever need real TLS, rebuild Witcher with OpenSSL
headers instead of using this shim.
"""

# Protocol/cert constants referenced as config defaults in gunicorn/config.py.
PROTOCOL_TLS = 2
PROTOCOL_SSLv23 = PROTOCOL_TLS
PROTOCOL_TLSv1 = 3
CERT_NONE = 0
CERT_OPTIONAL = 1
CERT_REQUIRED = 2

# Referenced by worker error handling (only on TLS sockets, never reached here).
SSL_ERROR_EOF = 8


class SSLError(OSError):
    """Placeholder; real TLS errors never occur on the plain-HTTP backend."""


def wrap_socket(*args, **kwargs):  # pragma: no cover - TLS disabled
    raise NotImplementedError(
        "ssl stub: TLS is not available under Witcher-python. "
        "Serve plain HTTP or rebuild the interpreter with OpenSSL."
    )

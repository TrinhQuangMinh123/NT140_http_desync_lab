#!/usr/bin/env python3
"""
advanced_level.py - Deep Obfuscation Mutators for Parser Confusion
------------------------------------------------------------------
These mutators go beyond HDHunter's standard corpus to exploit edge cases
in C/C++ HTTP parsers (like Nginx, HAProxy) vs Python/Java parsers (WSGI/Tomcat).

Features:
1. Whitespace injection (Vertical Tabs, Line Folding, Null bytes)
2. Unicode/Hex Encoding abuses (Full-width digits, illegal hex)
3. Header Key malformation (Space-before-colon)
"""

import random
import re


def obfuscate_whitespace(payload: bytes) -> bytes:
    """
    Inject strange whitespaces around critical headers.
    RFC7230 prohibits space between Header name and colon, but some 
    backends allow it while proxies drop or misinterpret it.
    """
    try:
        text = payload.decode('latin-1')
        
        # Whitespace dictionary: Vertical Tab, Form Feed, Null, Carriage Return Only, NBSP
        weird_spaces = ["\x0B", "\x0C", "\x00", "\r", "\t", " \t ", "\xa0"]
        space = random.choice(weird_spaces)

        # Mutate Content-Length
        if "Content-Length:" in text:
            # Inject space BEFORE colon (Request Smuggling classic: CL-TE desync)
            text = text.replace("Content-Length:", f"Content-Length{space}:")
            # Inject space AFTER colon
            text = text.replace("Content-Length: ", f"Content-Length:{space}")
            
        # Mutate Transfer-Encoding
        if "Transfer-Encoding:" in text:
            text = text.replace("Transfer-Encoding:", f"Transfer-Encoding{space}:")
            text = text.replace("Transfer-Encoding: chunked", f"Transfer-Encoding: {space}chunked{space}")

        # HTTP/1.1 Line Folding (obsolete but parsers still try to support it)
        # e.g. Transfer-Encoding:\r\n chunked
        if random.random() > 0.5:
            text = text.replace("Transfer-Encoding: chunked", "Transfer-Encoding:\r\n chunked")

        return text.encode('latin-1')
    except Exception:
        return payload


def obfuscate_unicode_encoding(payload: bytes) -> bytes:
    """
    Inject non-ASCII or otherwise odd encodings into Content-Length / chunk
    sizes to trip up parser number handling (paper §5.2.1).

    The whole HTTP request is built and shipped in latin-1 (so byte-level
    fidelity is preserved). To probe non-ASCII behaviour we explicitly
    splice UTF-8 bytes for full-width digits, then reassemble. The old
    implementation tried to `text.encode('latin-1')` containing full-width
    chars, which always threw and fell back to the original payload — no
    Unicode signal ever reached the server.
    """
    try:
        text = payload.decode('latin-1')

        # Strategies that stay in latin-1 (always safe to encode).
        ascii_strategies = [
            lambda x: f"+{x}",
            lambda x: f"-0{x}",
            lambda x: f"0x{int(x):x}",
            lambda x: x.zfill(len(x) + 3),  # extra zero padding
        ]

        if re.search(r"Content-Length: \d+", text):
            match = re.search(r"Content-Length: (\d+)", text)
            if match:
                cl_val = match.group(1)
                choice = random.random()
                if choice < 0.5:
                    # ASCII variant — safe path.
                    malformed = random.choice(ascii_strategies)(cl_val)
                    text = text.replace(
                        f"Content-Length: {cl_val}",
                        f"Content-Length: {malformed}",
                    )
                    out = text.encode('latin-1')
                else:
                    # UTF-8 full-width variant — splice raw UTF-8 bytes for
                    # the digits into the latin-1 stream so the encoded
                    # request really does contain U+FF10..U+FF19.
                    full_width = cl_val.translate(
                        str.maketrans("0123456789", "０１２３４５６７８９")
                    ).encode('utf-8')
                    head, _, tail = text.partition(f"Content-Length: {cl_val}")
                    out = (head.encode('latin-1')
                           + b"Content-Length: "
                           + full_width
                           + tail.encode('latin-1'))
                # Optional chunk-size obfuscation (always latin-1 safe).
                out_text = out.decode('latin-1')
                if re.search(r"\r\n([0-9a-fA-F]+)\r\n", out_text):
                    out_text = re.sub(
                        r"\r\n([0-9a-fA-F]+)\r\n",
                        r"\r\n0000000\1;ext=evil\r\n",
                        out_text,
                        count=1,
                    )
                    out = out_text.encode('latin-1')
                return out

        # No CL header to mutate: just maybe pad/extension a chunk size.
        if re.search(r"\r\n([0-9a-fA-F]+)\r\n", text):
            text = re.sub(
                r"\r\n([0-9a-fA-F]+)\r\n",
                r"\r\n0000000\1;ext=evil\r\n",
                text,
                count=1,
            )

        return text.encode('latin-1')
    except Exception:
        return payload


def inject_smuggling_prefix(payload: bytes) -> bytes:
    """
    Prepends junk or HTTP/0.9 preamble to confuse the proxy's boundary detection.
    Some WAFs drop it, some proxies forward it, backend misinterprets the start.
    """
    # Junk prefixes: CRLF, GET / HTTP/0.9
    prefixes = [
        b"\r\n\r\n\r\n",
        b"GET / HTTP/1.1\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",  # HTTP/2 Connection Preface
    ]
    
    return random.choice(prefixes) + payload

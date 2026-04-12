#!/usr/bin/env python3
"""
PCAP to Fuzzing Seed Extractor
------------------------------
Parses HTTP flows from captured PCAP files and extracts Start-Line, 
Field-Lines, and Message-Body segments into distinct fuzzing seeds.
"""

import sys
import os
import argparse
import logging

try:
    from scapy.all import rdpcap, TCP, Raw
except ImportError:
    print("[!] Error: 'scapy' library is missing.")
    print("[!] Please install it using: pip3 install scapy")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("SeedExtractor")

def extract_seeds_from_pcap(pcap_path, output_dir):
    """
    Reads a raw PCAP file and structurally splits each HTTP packet.
    Saves outputs as isolated '.txt' seeds inside 'output_dir'.
    """
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        logger.error(f"[!] Failed to read PCAP dataset: {e}")
        sys.exit(1)
        
    extracted_count = 0
    logger.info(f"[*] Analyzing network trace: {pcap_path} ...")
    
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw_payload = pkt[Raw].load
            
            # Use latin-1 decoding to prevent byte truncation issues
            http_data = raw_payload.decode('latin-1', errors='ignore')
            
            valid_methods = ("GET ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "HEAD ", "PATCH ", "PROPFIND ", "REPORT ", "TRACE ", "HTTP/1")
            
            if http_data.startswith(valid_methods):
                extracted_count += 1
                
                # Split HTTP payload via double CRLF (Standard sequence)
                # Note: This logic targets \r\n\r\n but we fallback to \n\n for anomalies
                if b"\r\n\r\n" in raw_payload:
                    parts = raw_payload.split(b"\r\n\r\n", 1)
                elif b"\n\n" in raw_payload:
                    parts = raw_payload.split(b"\n\n", 1)
                else:
                    parts = [raw_payload, b""]
                
                headers_block = parts[0]
                body_block = parts[1] if len(parts) > 1 else b""
                
                # Further extract the initial HTTP start line
                if b"\r\n" in headers_block:
                    header_lines = headers_block.split(b"\r\n", 1)
                else:
                    header_lines = headers_block.split(b"\n", 1)
                    
                start_line = header_lines[0]
                field_lines = header_lines[1] if len(header_lines) > 1 else b""
                
                logger.info(f"    [+] Seed #{extracted_count:03d} Extracted: {start_line.decode('latin-1')[:80]}")
                
                # Dump byte-perfect seed to local warehouse
                seed_filename = os.path.join(output_dir, f"seed_{extracted_count:03d}.txt")
                with open(seed_filename, "wb") as f:
                    f.write(b"---[START LINE]---\n")
                    f.write(start_line + b"\n\n")
                    f.write(b"---[FIELD LINES]---\n")
                    f.write(field_lines + b"\n\n")
                    f.write(b"---[BODY]---\n")
                    f.write(body_block + b"\n")
                    
    logger.info("-" * 65)
    logger.info(f"[√] Extraction Complete! Generated {extracted_count} raw HTTP seeds.")
    logger.info(f"[i] Output Directory: {os.path.abspath(output_dir)}/")

def main():
    parser = argparse.ArgumentParser(description="Extracts raw HTTP requests from PCAP files into Fuzzing seeds.")
    parser.add_argument("pcap_file", help="Path to the source PCAP file (e.g., traffic.pcap)")
    parser.add_argument("output_dir", help="Directory destination for extracted HTTP seeds")
    args = parser.parse_args()

    # Ensure targeted directory exists
    os.makedirs(args.output_dir, exist_ok=True)
    
    extract_seeds_from_pcap(args.pcap_file, args.output_dir)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
triage.py - HTTP Desync Taxonomy Classification (HDHunter)
-----------------------------------------------------------
Analyzes fuzzer-generated JSON crash reports and classifies them according
to the 4 primary academic criteria defined in the HDHunter paper:
1. Taxonomy (Desync Shapes)
2. Primary Discrepancies (Technical Deviations)
3. Attacks (Exploit Scenarios)
4. Insights (Root Causes)
"""

import os
import glob
import json
from collections import defaultdict

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "crash_reports")


def parse_reports(json_files):
    reports = []
    for file_path in json_files:
        try:
            with open(file_path, "r") as f:
                report = json.load(f)
                report["filename"] = os.path.basename(file_path)
                reports.append(report)
        except Exception as e:
            print(f"[!] Error reading file {file_path}: {e}")
    return reports


def classify_taxonomy(report: dict) -> str:
    """1. Taxonomy (Desync Shapes)"""
    rules = [r["rule"] for r in report.get("triggered_rules", [])]
    
    if 1 in rules or 2 in rules:
        return "Request-side: Inconsistent number of messages"
    elif 4 in rules or 5 in rules or 6 in rules:
        return "Request-side: Inconsistent message content"
    return "Response-side: Length discrepancy"


def classify_discrepancy(report: dict) -> str:
    """2. Primary Discrepancies (Technical Deviations)"""
    rules = [r["rule"] for r in report.get("triggered_rules", [])]
    mut_label = report.get("mutation_label", "").lower()
    
    if "perturb_content_length" in mut_label or 5 in rules:
        return "Non-standard number parsing"
    elif "trailer" in mut_label:
        return "Inconsistent trailer section handling"
    elif "obfuscate_transfer_encoding" in mut_label or (4 in rules and 5 in rules):
        return "Differing TE.CL handling strategies"
    elif 3 in rules:
        return "Incomplete response sanitization (Validation Bypass)"
    elif 7 in rules:
        return "Incomplete response sanitization (Raw byte difference)"
    
    return "Other"


def classify_attack(report: dict) -> str:
    """3. Attacks (Exploit Scenarios)"""
    rules = [r["rule"] for r in report.get("triggered_rules", [])]
    
    if 1 in rules or 2 in rules:
        return "Request Smuggling (Unauthorized request injection)"
    elif 3 in rules or 4 in rules or 5 in rules or 6 in rules:
        return "Request Confusing (Bypassing application logic)"
    return "Response Stealing / Forgery (Potential via length discrepancy)"


def classify_insight(report: dict) -> str:
    """4. Insights (Root Causes)"""
    mut_label = report.get("mutation_label", "").lower()
    
    if "perturb_content_length" in mut_label or "byte" in mut_label:
        return "Programming language quirks (Number Parsing routines)"
    elif "trailer" in mut_label:
        return "Rarely-used feature handling (Trailer Sections)"
    elif "token_replace" in mut_label or "swap" in mut_label:
        return "Non-standard HTTP RFC compliance"
    return "Protocol translation issues (Proxy vs WSGI/CGI Mismatch)"


def print_section(title, counter, total):
    print(f"\n\033[1;96m{title}\033[0m")
    print("=" * 60)
    
    # Sort by count descending
    for category, count in sorted(counter.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total) * 100
        # Highlight critical findings
        color = "\033[91m" if "Smuggling" in category or "Inconsistent number" in category else "\033[0m"
        print(f"  {color}► {category}: {count} reports ({percentage:.1f}%)\033[0m")


def main():
    if not os.path.exists(REPORTS_DIR):
        print(f"[!] Crash reports directory not found at: {REPORTS_DIR}")
        return

    json_files = glob.glob(os.path.join(REPORTS_DIR, "*.json"))
    if not json_files:
        print(f"[!] No JSON reports found in {REPORTS_DIR}")
        return

    reports = parse_reports(json_files)
    total = len(reports)
    
    print("=" * 70)
    print("  HDHUNTER TAXONOMY & HTTP DESYNC ANALYSIS")
    print(f"  Total discrepancies analyzed: {total}")
    print("=" * 70)

    # Initialize counters
    tax_count = defaultdict(int)
    disc_count = defaultdict(int)
    atk_count = defaultdict(int)
    ins_count = defaultdict(int)

    for r in reports:
        tax_count[classify_taxonomy(r)] += 1
        disc_count[classify_discrepancy(r)] += 1
        atk_count[classify_attack(r)] += 1
        ins_count[classify_insight(r)] += 1

    print_section("1. Taxonomy (Desync Shapes)", tax_count, total)
    print_section("2. Primary Discrepancies (Technical Deviations)", disc_count, total)
    print_section("3. Attacks (Exploit Scenarios)", atk_count, total)
    print_section("4. Insights (Root Causes)", ins_count, total)

    # Highlight a classic Request Smuggling example
    print("\n\033[1;93m[*] Notable Request Smuggling Example (Pipeline Desync):\033[0m")
    for r in reports:
        if "Inconsistent number" in classify_taxonomy(r):
            print(f"  - File: {r['filename']}")
            print(f"  - Mutator used: {r.get('mutation_label')}")
            proxy_count = r['proxy_state']['message_count']
            direct_count = r['direct_state']['message_count']
            print(f"  - Detail: Proxy detected {proxy_count} request(s), but Backend detected {direct_count} request(s).")
            break 
    print()

if __name__ == "__main__":
    main()

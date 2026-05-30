#!/usr/bin/env python3
"""
triage.py - HTTP Desync Taxonomy Classification (HDHunter)
-----------------------------------------------------------
Analyzes fuzzer-generated JSON crash reports and classifies them according
to 4 HDHunter-inspired criteria. The labels are prioritization hints, not
proof that a report is exploitable:
1. Taxonomy (Desync Shapes)
2. Primary Discrepancies (Technical Deviations)
3. Attack Candidates (Exploitability Signals)
4. Insights (Hypothesized Root Causes)
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
    """1. Taxonomy (Desync Shapes) — wording reflects OBSERVED responses,
    not parser-internal request count (project does not instrument the
    parser; see diff_checker.py module docstring)."""
    rules = [r["rule"] for r in report.get("triggered_rules", [])]

    if 1 in rules or 2 in rules:
        return "Possible Request-side Desync: paths emitted different numbers of HTTP responses"
    elif 4 in rules or 5 in rules or 6 in rules:
        return "Possible Request-side Desync: response content/length differs"
    return "Response-side: length/order discrepancy"


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
    """3. Attack candidates (exploitability signals, not proof)"""
    rules = [r["rule"] for r in report.get("triggered_rules", [])]
    
    if 1 in rules or 2 in rules:
        return "Request Smuggling candidate (requires replay/PoC)"
    elif 3 in rules or 4 in rules or 5 in rules or 6 in rules:
        return "Request Confusing candidate (requires semantic validation)"
    return "Response Stealing/Forgery candidate (requires response-queue PoC)"


def classify_insight(report: dict) -> str:
    """4. Insights (hypothesized root causes)"""
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


def print_stability_summary(reports):
    """Print repeat-run stability when reports contain repeat metadata."""
    repeat_reports = [r for r in reports if r.get("repeat_analysis")]
    if not repeat_reports:
        return

    stable = 0
    unstable = 0
    total_discrepancy_runs = 0
    total_completed_repeats = 0
    for report in repeat_reports:
        analysis = report["repeat_analysis"]
        total_discrepancy_runs += analysis.get("discrepancy_runs", 0)
        total_completed_repeats += analysis.get(
            "completed_repeats",
            analysis.get("repeat_count", 0),
        )
        if analysis.get("stable_discrepancy"):
            stable += 1
        else:
            unstable += 1

    print("\n\033[1;96m5. Repeat Stability\033[0m")
    print("=" * 60)
    print(f"  Reports with repeat metadata: {len(repeat_reports)}")
    print(f"  Stable discrepancies: {stable}")
    print(f"  Unstable discrepancies: {unstable}")
    if total_completed_repeats:
        rate = (total_discrepancy_runs / total_completed_repeats) * 100
        print(f"  Reproduction rate across completed repeated runs: {rate:.1f}%")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Triage HTTP Desync crash reports")
    parser.add_argument("--label", default="", help="Filter reports by target label (e.g., nginx_gunicorn)")
    parser.add_argument("--reports-dir", default=REPORTS_DIR,
                        help="Directory containing discrepancy JSON reports")
    parser.add_argument("--recursive", action="store_true",
                        help="Scan reports-dir recursively for discrepancy JSON reports")
    args = parser.parse_args()

    reports_dir = os.path.abspath(args.reports_dir)
    if not os.path.exists(reports_dir):
        print(f"[!] Crash reports directory not found at: {reports_dir}")
        return

    pattern = "**/*.json" if args.recursive else "*.json"
    json_files = glob.glob(os.path.join(reports_dir, pattern), recursive=args.recursive)
    json_files = [f for f in json_files if os.path.basename(f).startswith("discrepancy_")]
    if args.label:
        json_files = [f for f in json_files if args.label in os.path.basename(f)]

    if not json_files:
        print(f"[!] No JSON reports found in {reports_dir} for label '{args.label}'")
        return

    reports = parse_reports(json_files)
    total = len(reports)
    
    print("=" * 70)
    print("  HDHUNTER-INSPIRED TAXONOMY & HTTP DESYNC ANALYSIS")
    print(f"  Reports Dir: {reports_dir}")
    if args.label:
        print(f"  Target Filter: {args.label}")
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
    print_section("3. Attack Candidates (Exploitability Signals)", atk_count, total)
    print_section("4. Insights (Hypothesized Root Causes)", ins_count, total)
    print_stability_summary(reports)

    # Highlight a candidate that should be replayed manually.
    print("\n\033[1;93m[*] Notable Pipeline-Desync Candidate (Smuggling shortlist):\033[0m")
    found_candidate = False
    for r in reports:
        if "different numbers of HTTP responses" in classify_taxonomy(r):
            found_candidate = True
            print(f"  - File: {r['filename']}")
            print(f"  - Mutator used: {r.get('mutation_label')}")
            # Field names changed (proxy_state.observed_response_count); fall
            # back to old key for backwards compat with archived reports.
            proxy_count = (r['proxy_state'].get('observed_response_count')
                           or r['proxy_state'].get('message_count'))
            direct_count = (r['direct_state'].get('observed_response_count')
                            or r['direct_state'].get('message_count'))
            print(f"  - Detail: Proxy path observed {proxy_count} HTTP response(s), "
                  f"backend-direct path observed {direct_count}. "
                  f"This is a wire-level observation, NOT proof of a hidden request — "
                  f"replay + traffic capture required before calling this exploitable.")
            break
    if not found_candidate:
        print("  - None in the selected report set.")
    print()

if __name__ == "__main__":
    main()

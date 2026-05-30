#!/usr/bin/env python3
"""analyze_cov_baseline.py — B6 + B8 analysis over a `runner.py --witcher --trace-log` JSONL.

Consumes the per-case trace (one JSON line per logical case, includes the real
HttpParam state + cov_fingerprint for BOTH proxy and direct paths) and reports:

  Coverage faithfulness : fraction of cases with a real Witcher cov_fingerprint.
  B6 (corroboration)    : of the discrepancies, how many are backed by a REAL
                          backend parse-state divergence (proxy-parse ≠ direct-parse)
                          vs response-observation-only (real state identical → the
                          rule-1/rule-7 trigger is a wire artifact, needs replay).
  B8 (coverage blind)   : cov_fingerprint groups that map to >1 distinct REAL parse
                          state — same edges, different framing. Quantifies the
                          "coverage is blind to number/length parsing" hypothesis.

Usage: python3 analyze_cov_baseline.py <trace.jsonl>
"""
import json
import sys
import collections


def real_state(side):
    """The backend's true per-message parse state (paper Count/Consumed/Encoding/CL)."""
    return (
        side["count_real"],
        tuple(side["consumed_real"] or []),
        tuple(side["chunked_real"] or []),
        tuple(side["content_length_real"] or []),
    )


def main(path):
    recs = [json.loads(l) for l in open(path) if l.strip()]
    n = len(recs)
    print("=" * 68)
    print(f"  COVERAGE+STATE BASELINE ANALYSIS  (n={n} cases)  src={path}")
    print("=" * 68)

    with_fp = [r for r in recs if r["direct"]["cov_fingerprint"]]
    distinct = {r["direct"]["cov_fingerprint"] for r in with_fp}
    print(f"\n[Coverage] direct cov_fingerprint present : {len(with_fp)}/{n} "
          f"({100*len(with_fp)//max(n,1)}%)   distinct: {len(distinct)}")

    disc = [r for r in recs if r["is_discrepancy"]]
    corrob = [r for r in disc if real_state(r["proxy"]) != real_state(r["direct"])]
    resp_only = [r for r in disc if real_state(r["proxy"]) == real_state(r["direct"])]
    print(f"\n[B6] discrepancies                         : {len(disc)}")
    print(f"     corroborated by REAL state divergence  : {len(corrob)}")
    print(f"     response-observation-only (real same)  : {len(resp_only)}")

    by_fp = collections.defaultdict(set)
    for r in with_fp:
        by_fp[r["direct"]["cov_fingerprint"]].add(real_state(r["direct"]))
    blind = [(fp, s) for fp, s in by_fp.items() if len(s) > 1]
    print(f"\n[B8] fingerprint groups with >1 real state : {len(blind)} "
          f"(coverage-blind: same edges, different parse)")
    for fp, states in blind:
        print(f"     fp {fp[:12]}.. -> {len(states)} states:")
        for s in states:
            print(f"        count={s[0]} consumed={list(s[1])} "
                  f"chunked={list(s[2])} CL={list(s[3])}")
    print("=" * 68)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "trace_cov_b5.jsonl")

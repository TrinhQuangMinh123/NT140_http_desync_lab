#!/usr/bin/env python3
"""analyze_witcher_full.py — aggregate the full-scale faithful run into result.md-style
tables PLUS the paper-faithful extras (B6 corroboration, B8 coverage-blind groups).

Consumes every 05_analyzer/trace_full_<env>_<seed>.jsonl produced by run_witcher_full.sh
(env+seed parsed from the filename) and prints Markdown sections directly comparable to
result.md §2/§3/§5 — but every cell is now backed by REAL Witcher coverage + HttpParam
internal state, for the gunicorn-backed envs only.

Usage: python3 analyze_witcher_full.py [glob_dir]
"""
import json
import glob
import os
import re
import sys
import collections
import statistics

RULE_FIELD = {
    1: "observed_response_count", 2: "observed_messages_parsed", 3: "status",
    4: "transfer_encoding", 5: "content_length", 6: "body_length",
    7: "raw_response_length", 8: "response_order", 9: "body_hash",
}
SEEDS = ["1337", "1338", "1339", "1340", "1341"]
# Display order + pretty names (matches result.md rows where they correspond).
ENV_ORDER = ["nginx_gunicorn", "haproxy_gunicorn", "ats_gunicorn"]
ENV_PRETTY = {
    "nginx_gunicorn": "NGINX 1.25 -> Gunicorn",
    "haproxy_gunicorn": "HAProxy 2.9 -> Gunicorn",
    "ats_gunicorn": "ATS -> Gunicorn (gevent swapped, see note)",
}


def real_state(side):
    return (side["count_real"], tuple(side["consumed_real"] or []),
            tuple(side["chunked_real"] or []), tuple(side["content_length_real"] or []))


def load(trace_dir):
    """-> {env: {seed: [records]}}"""
    data = collections.defaultdict(lambda: collections.defaultdict(list))
    pat = re.compile(r"trace_full_(.+)_(\d{4})\.jsonl$")
    for path in sorted(glob.glob(os.path.join(trace_dir, "trace_full_*.jsonl"))):
        m = pat.search(os.path.basename(path))
        if not m:
            continue
        env, seed = m.group(1), m.group(2)
        recs = [json.loads(l) for l in open(path) if l.strip()]
        data[env][seed] = recs
    return data


def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |",
           "|" + "|".join("---" for _ in header) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def main(trace_dir):
    data = load(trace_dir)
    envs = [e for e in ENV_ORDER if e in data] + [e for e in data if e not in ENV_ORDER]
    if not envs:
        print("no trace_full_*.jsonl found in", trace_dir)
        return

    total_cases = sum(len(r) for e in data.values() for r in e.values())
    total_disc = sum(1 for e in data.values() for r in e.values() for x in r if x["is_discrepancy"])
    print(f"# Full-scale faithful analysis  ({trace_dir})\n")
    print(f"- Envs: {', '.join(envs)}")
    print(f"- Total logical cases: {total_cases}   Total discrepancies: {total_disc} "
          f"({100*total_disc/max(total_cases,1):.1f}%)\n")

    # ── §3-style: per-env per-seed discrepancy counts ────────────────────────
    print("## Request-side discrepancies per env x seed\n")
    rows = []
    grand = [0] * len(SEEDS)
    for env in envs:
        cells, tot = [], 0
        for i, s in enumerate(SEEDS):
            c = sum(1 for x in data[env].get(s, []) if x["is_discrepancy"])
            n = len(data[env].get(s, []))
            cells.append(c)
            tot += c
            grand[i] += c
        ncases = sum(len(data[env].get(s, [])) for s in SEEDS)
        mean = statistics.mean(cells) if cells else 0
        sd = statistics.pstdev(cells) if len(cells) > 1 else 0
        hit = 100 * tot / max(ncases, 1)
        rows.append([ENV_PRETTY.get(env, env)] + cells +
                    [tot, f"{mean:.1f}", f"+/-{sd:.2f}", f"{hit:.1f}%"])
    gtot = sum(grand)
    gcases = total_cases
    rows.append(["**Total**"] + grand + [f"**{gtot}**", "", "",
                 f"**{100*gtot/max(gcases,1):.1f}%**"])
    print(md_table(["Env"] + [f"s{s}" for s in SEEDS] +
                   ["Tong", "Mean", "Stddev", "Hit rate"], rows))
    print()

    # ── §5-style: rule frequency per env (over all 5 seeds) ──────────────────
    print("## Rule frequency per env (all 5 seeds)\n")
    rrows = []
    for env in envs:
        cnt = collections.Counter()
        for s in SEEDS:
            for x in data[env].get(s, []):
                for rl in x.get("rules", []):
                    cnt[rl] += 1
        rrows.append([ENV_PRETTY.get(env, env)] + [cnt.get(r, 0) for r in range(1, 10)])
    print(md_table(["Env"] + [f"R{r}" for r in range(1, 10)], rrows))
    print()

    # ── B6 + B8 per env, and combined ────────────────────────────────────────
    print("## B6 internal-state corroboration + B8 coverage-blind (per env)\n")
    brows = []
    for env in envs:
        allrecs = [x for s in SEEDS for x in data[env].get(s, [])]
        disc = [x for x in allrecs if x["is_discrepancy"]]
        corrob = [x for x in disc if real_state(x["proxy"]) != real_state(x["direct"])]
        with_fp = [x for x in allrecs if x["direct"]["cov_fingerprint"]]
        by_fp = collections.defaultdict(set)
        for x in with_fp:
            by_fp[x["direct"]["cov_fingerprint"]].add(real_state(x["direct"]))
        blind = [fp for fp, st in by_fp.items() if len(st) > 1]
        brows.append([ENV_PRETTY.get(env, env), len(allrecs),
                      f"{len(with_fp)} ({100*len(with_fp)//max(len(allrecs),1)}%)",
                      len({x["direct"]["cov_fingerprint"] for x in with_fp}),
                      len(disc), len(corrob), len(disc) - len(corrob), len(blind)])
    print(md_table(["Env", "Cases", "cov present", "distinct fp",
                    "Disc", "B6 corrob", "B6 resp-only", "B8 blind groups"], brows))
    print()

    # ── B8 examples (combined) ────────────────────────────────────────────────
    print("## B8 examples — same coverage fingerprint, different REAL parse state\n")
    shown = 0
    for env in envs:
        allrecs = [x for s in SEEDS for x in data[env].get(s, []) if x["direct"]["cov_fingerprint"]]
        by_fp = collections.defaultdict(set)
        for x in allrecs:
            by_fp[x["direct"]["cov_fingerprint"]].add(real_state(x["direct"]))
        for fp, st in by_fp.items():
            if len(st) > 1 and shown < 8:
                print(f"- `{env}` fp `{fp[:12]}..` -> {len(st)} states:")
                for s in st:
                    print(f"    count={s[0]} consumed={list(s[1])} chunked={list(s[2])} CL={list(s[3])}")
                shown += 1
    if not shown:
        print("(none)")
    print()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__)))

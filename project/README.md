# 🕷️ HTTP Desync Differential Fuzzer

A differential testing framework for detecting **HTTP Request Smuggling (HTTP Desync)** vulnerabilities. Inspired by the academic research paper and toolchain of [HDHunter](https://github.com/hexian2001/HDHunter), rebuilt in Python and Docker for accessibility and extensibility.

---

## How It Works

The core idea is **differential testing**: send the same mutated HTTP request to both a **Reverse Proxy** and a **Backend Server** over independent raw TCP connections. If they parse it differently (different message count, status code, body length, etc.), a desync vulnerability exists.

```
                         ┌─────────────────────┐
                         │   Mutated Payload    │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┴─────────────────────┐
              │  (raw TCP)                    (raw TCP)    │
              ▼                                            ▼
   ┌─────────────────┐                      ┌─────────────────────┐
   │  Reverse Proxy  │                      │   Backend (Direct)  │
   │  (e.g. Nginx)   │──forwards via HTTP──▶│  (e.g. Gunicorn)    │
   └────────┬────────┘                      └──────────┬──────────┘
            │ State Tuple JSON                          │ State Tuple JSON
            └────────────────────┬──────────────────────┘
                                 ▼
                        ┌─────────────────┐
                        │  diff_checker   │ ← Apply 7 HDHunter Rules
                        └────────┬────────┘
                                 │ Discrepancy?
                                 ▼
                        crash_reports/*.json
```

---

## Project Structure

```
project/
├── 01_data_prep/
│   ├── collector.py          # Golden Seed Corpus generator (12 seeds)
│   └── seeds_db/             # Output: raw HTTP seed files
│
├── 02_targets/
│   ├── nginx_gunicorn/       # Nginx (port 8888) → Gunicorn (port 9001)
│   ├── haproxy_flask/        # HAProxy (port 8890) → Gunicorn (port 9003)
│   ├── ats_gevent/           # Apache Traffic Server (port 8889) → Gevent (port 9002)
│   └── apache_tomcat/        # Apache HTTPD (port 8891) → Tomcat (port 9004)
│
├── 03_mutator/
│   ├── sequence_level.py     # Splice, Remove (pipeline mutations)
│   ├── message_level.py      # Header duplicate, swap, token replace
│   ├── byte_level.py         # Raw byte mutations, TE/CL obfuscation
│   ├── advanced_level.py     # Unicode bypass, whitespace injection, prefixes
│   └── tokens.json           # Token dictionary for header value replacement
│
├── 04_fuzzer_engine/
│   ├── runner.py             # Main fuzzing loop (raw TCP, multi-target)
│   └── diff_checker.py       # 7 differential rules (HDHunter's http_param.rs)
│
├── 05_analyzer/
│   ├── triage.py             # HDHunter Taxonomy classifier (4 categories)
│   └── crash_reports/        # Output: .json + .payload per discrepancy
│
├── 06_exploits_poc/
│   └── exploit_smuggling.py  # Weaponized PoC from a discovered payload
│
├── 07_mini_test_suite/
│   └── test_proxy_backend.py # Standalone demo: proxy vs backend parsing diff
│
└── run_all.sh                # One-command orchestrator for all targets
```

---

## Target Environments

| # | Proxy | Backend | Proxy Port | Backend Port |
|---|-------|---------|------------|--------------|
| 1 | **Nginx 1.25** | Gunicorn (WSGI) | 8888 | 9001 |
| 2 | **HAProxy 2.9** | Gunicorn (WSGI) | 8890 | 9003 |
| 3 | **Apache Traffic Server** | Gevent (Python) | 8889 | 9002 |
| 4 | **Apache HTTPD 2.4** | Apache Tomcat 10 | 8891 | 9004 |

All proxy configurations deliberately **disable header normalization** to expose raw parser behavior differences.

---

## Mutation Engine

The fuzzer applies mutations across 3 levels, with 14 total strategies:

### Sequence Level
| Mutator | Description |
|---------|-------------|
| `sequence_splice` | Fuse two seeds into a pipelined request |
| `sequence_remove` | Remove a segment from a pipeline |

### Message Level
| Mutator | Description |
|---------|-------------|
| `field_line_duplicate` | Duplicate a random header |
| `field_line_remove` | Drop a random header |
| `node_token_replace` | Swap a header token (e.g. `chunked` → `identity`) |
| `node_typed_swap` | Exchange two headers with each other |

### Byte Level
| Mutator | Description |
|---------|-------------|
| `byte_insert` | Insert a random byte |
| `byte_remove` | Delete a random byte |
| `byte_duplicate` | Repeat a byte |
| `obfuscate_transfer_encoding` | Mangle TE value (`\tchunked`, `CHunKed`, etc.) |
| `perturb_content_length` | Corrupt CL value (`-1`, `999`, `0`) |
| `obfuscate_whitespace` ⚡ | Inject `\x0B`, `\x00`, `\r` into header names |
| `obfuscate_unicode_encoding` ⚡ | Replace digits with full-width Unicode (`１０`, `0xa`) |
| `inject_smuggling_prefix` ⚡ | Prepend HTTP/2.0 preface or junk preamble |

> ⚡ = Advanced mutators targeting C/C++ parser weaknesses (Nginx, HAProxy).

**Test case count:**
```
Total = Seeds × (1 original + N mutations)
      = 12 × (1 + N)

--mutations 3  →  48 cases   (quick scan)
--mutations 10 →  132 cases  (standard)
--mutations 20 →  252 cases  (recommended for reports)
```

---

## Golden Seed Corpus

12 pre-crafted seeds, each targeting a distinct HTTP/1.1 edge case:

| Seed | Edge Case |
|------|-----------|
| `seed_01` | Standard GET request (baseline) |
| `seed_02` | POST with Content-Length |
| `seed_03` | POST with Transfer-Encoding: chunked |
| `seed_04` | **TE Line Folding** (`Transfer-Encoding:\r\n chunked`) |
| `seed_05` | **Absolute URI** (`GET http://localhost/ HTTP/1.1`) |
| `seed_06` | **Duplicate Content-Length** headers |
| `seed_07` | **CL.TE conflict** (proxy uses CL, backend uses TE) |
| `seed_08` | **TE.CL conflict** (proxy uses TE, backend uses CL) |
| `seed_09` | Chunk Extension (`5;ext=evil`) |
| `seed_10` | Trailer Headers (after chunked body) |
| `seed_11` | **Pipelining** (two requests on one connection) |
| `seed_12` | Padded Content-Length (`Content-Length: 00011`) |

---

## Differential Rules (7 Rules from HDHunter)

`diff_checker.py` implements the exact comparison logic from HDHunter's `http_param.rs`:

| Rule | Field | Triggers When |
|------|-------|---------------|
| 1 | `message_count` | Proxy and backend see different number of messages |
| 2 | `message_processed` | One side processed more complete messages |
| 3 | `status` | HTTP status codes differ |
| 4 | `transfer_encoding` | One side stripped/added TE header |
| 5 | `content_length` | CL value was rewritten in transit |
| 6 | `body_length` | Consumed body bytes differ |
| 7 | `consumed_length` | Raw response size differs |

---

## Triage — HDHunter Taxonomy

`triage.py` classifies all discrepancies into 4 academic categories:

| Category | Description |
|----------|-------------|
| **Taxonomy** | Desync shape: Inconsistent number / content / response-side |
| **Discrepancies** | Root deviation: Non-standard parsing, TE.CL conflict, sanitization failure |
| **Attacks** | Exploit potential: Request Smuggling, Request Confusing, Response Forgery |
| **Insights** | Root cause: Language quirks, RFC non-compliance, Protocol mismatch |

---

## Quickstart

**Requirements:** Python 3.10+, Docker with Compose plugin.

```bash
# 1. Start Nginx + Gunicorn target
cd project/02_targets/nginx_gunicorn
docker compose up -d --build

# 2. Generate Golden Seed Corpus
cd project/01_data_prep
python3 collector.py

# 3. Run the fuzzer
cd project/04_fuzzer_engine
python3 runner.py --mutations 10 --quiet

# 4. Triage and classify findings
cd project/05_analyzer
python3 triage.py

# OR: run everything with one command
bash project/run_all.sh
```

**Multi-target fuzzing:**
```bash
python3 runner.py --proxy-port 8890 --backend-port 9003 --label haproxy_flask --mutations 10 --quiet
```

**Mini standalone demo (for presentations):**
```bash
python3 project/07_mini_test_suite/test_proxy_backend.py
```

---

## Key Files Reference

| File | Why It Matters |
|------|----------------|
| `04_fuzzer_engine/diff_checker.py` | The 7 differential rules — the academic core of the project |
| `02_targets/nginx_gunicorn/backend/app.py` | State Tuple JSON backend replacing HDHunter's QEMU shared memory |
| `05_analyzer/triage.py` | HDHunter Taxonomy classifier — highest academic value |
| `03_mutator/advanced_level.py` | Extended mutators beyond the original paper |
| `07_mini_test_suite/test_proxy_backend.py` | Self-contained demo for live presentations |

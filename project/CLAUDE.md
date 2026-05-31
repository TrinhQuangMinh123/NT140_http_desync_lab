# CLAUDE.md — HTTP Desync Differential Fuzzer (đồ án trên nền HDHunter)

## Dự án là gì
Công cụ **differential fuzzing** phát hiện HTTP Desync: gửi cùng 1 request (đã mutate) qua
**reverse-proxy** và thẳng vào **backend** qua raw TCP, so **State Tuple** 2 bên, áp "7 HDHunter Rules"
trong `diff_checker.py` để gắn cờ desync. Đây là bản **tự dựng lại phương pháp** của paper HDHunter
(USENIX Sec '25) — KHÔNG replicate 1:1 engine.

- **Phase 1 (XONG):** đo đúng-paper request-side trên 2 tầng — coverage gray-box (Witcher-python bitmap)
  + internal-state HttpParam thật. Baseline 719 case / 3 env, xem `docs/resultv2.md`.
- **Phase 2 (ĐANG MỞ ĐẦU):** tích hợp LLM. Lý lẽ + invariant: `docs/IDEA_llm_integration.md`.
  Điều kiện sống còn = điểm mù B8 phải có lớp **structural** (vượt ngoài number-format mà dictionary phủ được),
  nếu không thì "cần gì LLM" không trả lời được. Đang chạy run v3 để kiểm (xem "Đang ở đâu").

## Cấu trúc code & luồng dữ liệu (đọc cái này trước khi sửa)
Pipeline 5 stage đánh số. **Luồng request-side faithful** (chế độ chính):
`runner.py` nạp 12 seed → mutate (03) → `WitcherBackend` compose up (inject shm id) → mỗi case:
`reset shm → send PROXY → read_coverage+read_state → reset → send DIRECT → read → compare()` → trace + report.

- **`01_data_prep/`** — `seeds_db/` = **12 golden request seed** (các edge-case HTTP/1.1 mơ hồ: dup CL, TE.CL,
  CL.TE, trailer, pipelining, padded/hex CL). `response_seeds_db/` = 5 seed cho response-side. `collector.py`/`parser.py` = pcap→seed.
- **`02_targets/<env>/`** — mỗi env = config proxy + `backend/` (gunicorn WSGI app). 4 env:
  `nginx_gunicorn` (**chính chủ**), `haproxy_flask`, `ats_gevent`, `apache_tomcat`.
  - ⚠️ **Backend instrument sống ở MỘT chỗ:** `nginx_gunicorn/backend/`. haproxy & ats `compose.witcher`
    đều `build context: ../nginx_gunicorn/backend` → **vá 1 lần, cả 3 env hưởng** (Tomcat=Java không faithful được, §9 resultv2).
  - Trong `nginx_gunicorn/backend/`: `vendor_py/gunicorn/http/{message,body}.py` (parser ĐÃ VÁ ghi HttpParam),
    `hdhunter.py` (**shim** ctypes→SysV shm, API `inc_consumed/inc_body/set_cl/set_chunked/mark_processed`),
    `Dockerfile.witcher`, `witcher_filter.txt`, `app.py` (WSGI + init shm).
  - compose: `docker-compose.yml` (baseline **coverage.py**, nhóm A/B đối chứng) · `docker-compose.witcher.yml`
    (+`.override.yml`) (**faithful**, ipc:host, bare-key passthrough shm id) · `.wiretap.yml`.
- **`03_mutator/`** — 4 tầng operator: `byte_level`/`message_level`/`sequence_level`/`advanced_level` + `tokens.json`.
  `runner.mutate_payload()` chọn ngẫu nhiên theo tầng; `sequence:*` dùng corpus donor.
- **`04_fuzzer_engine/`** — lõi:
  - `runner.py` — driver. `run_fuzzer()` (request-side) + `run_fuzzer_response()`. CLI chính: `--witcher`,
    `--mutations`, `--random-seed`, `--reports-dir`, `--trace-log`, `--witcher-compose-base/-override`, `--witcher-no-build`.
  - `diff_checker.py` — `StateTuple` (observed-response + `*_real` từ shm) + 7 rule + `compare()`.
  - `hdhunter_shm.py` — `WitcherShm` (tạo/đọc 3 SysV shm: AFL bitmap 65536, EXECUTION_PATH, HttpParam) +
    `WitcherBackend` (context manager compose up/down). `read_state()` trả **dict đầy đủ** HttpParam.
  - `fake_upstream.py` (response-side origin), `wire_tap.py`.
- **`05_analyzer/`** — `trace_*.jsonl` (1 dòng/case, input cho B6/B8) · `crash_reports_*/` · drivers
  `run_witcher_full.sh` (v2) / `run_witcher_v3.sh` (v3) · `analyze_witcher_full.py` (aggregator §3/§6/§8) ·
  `analyze_cov_baseline.py`, `triage.py` · `RESULT_*.md`.
- **`06_exploits_poc/`**, **`07_mini_test_suite/`**, **`docs/`** (plan/notes/idea/resultv2).

> **Host-side vs container-side:** `runner.py`/`diff_checker.py`/`hdhunter_shm.py`/`analyze_*` chạy trên HOST →
> sửa là ăn ngay. `vendor_py/*` + `hdhunter.py` shim + `app.py` nằm TRONG image → **phải rebuild** (`up --build`).

## Quyết định đã chốt (chi tiết: REPO_UPSTREAM_NOTES.md)
- **R1+A/R2:** coverage = Witcher-python bitmap (`__AFL_SHM`, edge=`hash(f_lasti,f_lineno)%65536`), tái lập TÍN HIỆU,
  KHÔNG QEMU-Nyx (vướng WSL2). **R13:** `__EXECUTION_PATH` = SysV shm **ID** (không phải path; thiếu → segfault).
- **R9:** mỗi request log `cov_fingerprint` = hash tập edge chạm → probe điểm mù B8.
- **R11/R12:** internal-state 7-tuple thật = pure-Python ctypes→libc SysV shm (KHÔNG build Rust .so).
- **Faithful = 3/4 env** (nginx/haproxy/ats → gunicorn-under-Witcher). Tomcat (Java) hoãn — giới hạn công cụ.

## Đang ở đâu / pick up từ đây
- **✅ Phase 1 v2 XONG:** 719 case · 403 disc (56.1%) · coverage 99.9% · 7-tuple thật. **B6**: desync framing
  thật NGINX 63% > HAProxy 34% > ATS 26%. **B8**: 5 nhóm điểm mù/env, tái lập 3 proxy. Báo cáo `docs/resultv2.md`.
- **🔑 Phát hiện 2026-05-31:** trên dữ liệu v2, **100% (15/15) nhóm B8 là numeric-only** (chỉ khác giá trị
  `consumed`/`CL`), **0 structural** → đúng lớp một **dictionary number-format tĩnh** phủ được → luận điểm "cần LLM"
  CHƯA đứng. NHƯNG có lỗ hổng đo: trace cũ chỉ log 4/8 field HttpParam; `consumed==body` (không đếm framing).
- **✅ Refactor "B4b v2" (đã làm, đã smoke-test):** để structural blind-spot hiện ra nếu có —
  - `body.py`: tách `consumed` (kể cả byte framing chunk-size line/CRLF/trailer) khỏi `body` (payload decode)
    → trục structural `consumed−body`. Smoke OK: trailer cho `consumed=[109] body=[11]`.
  - `hdhunter_shm.read_state()` → **dict đầy đủ** (+`body_length_real`/`status_real`/`order_real`/raw).
    `status`/`order` KHÔNG được parser request-side ghi (luôn 0) — surface verbatim, không giả tín hiệu.
  - `diff_checker.StateTuple` + `runner` wiring (vals/save_report/trace) + `analyze_witcher_full.py`
    (khóa B8 +`body`; **phân loại structural vs numeric**, hàm `classify_blind`).
- **⏳ ĐANG CHẠY (nền):** `05_analyzer/run_witcher_v3.sh` — 3 env × 8 seed (1337–1344) × mut=50 ≈ **14,688 case**
  → `trace_full_v3_*` / `crash_reports_cov_v3_*` (KHÔNG đụng v2). Log: `05_analyzer/run_v3.log`. ~1.5–2h.
- **➡️ VIỆC TIẾP (task #7):** run xong → `python3 05_analyzer/analyze_witcher_full.py 05_analyzer` lọc file v3
  → đọc cột **B8 structural vs numeric**. **Quy tắc quyết định (đã chốt trước):**
  structural > 0 quy mô lớn → luận điểm LLM **per-pair** đứng → thiết kế Phase 2 quanh chúng;
  vẫn 0 → kết luận trung thực dictionary đủ, vai trò LLM pivot sang triage/verify (Trục 1b IDEA doc).
- **Ablation Phase 2 phải 3 nhánh** (không phải 2): coverage-only · +static-dictionary · +LLM — nếu không,
  win của LLM không falsifiable (xem lập luận đã chốt trong phiên, memory `phase1-done-phase2-llm-plan`).

## Gotchas
- Bash tool **reset cwd về `project/` mỗi lệnh** — **dùng đường dẫn tuyệt đối** (compose `-f` cũng vậy, không sẽ nhân đôi path).
- HttpParam struct (328B, khớp 2 phía host↔container): `content_length[i64;10]`, `chunked_encoding[i8;10]`,
  `consumed_length[i64;10]`, `body_length[i64;10]`, `message_count i32`, `message_processed i8`,
  `status[i16;10]`, `order[i32;10]`. `clear()` set length-field = -1 (sentinel) trước mỗi request.
- shm tạo mode **0666** (container userns-remap). `ipc: host` bắt buộc. Backend gunicorn `--workers 1 --preload` (tất định).
- Sửa parser/shim/app → **phải `up --build`** mới ăn (driver v3 build seed đầu mỗi env, no-build các seed sau).
- Metric đánh giá = time-to-first-discrepancy + số *loại* discrepancy/ngân sách — KHÔNG phải coverage cuối.
- Response-side KHÔNG faithful được (origin là FakeUpstream, đo response-parser proxy C chưa instrument) — chỉ breadth demo.

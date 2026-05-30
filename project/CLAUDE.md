# CLAUDE.md — HTTP Desync Differential Fuzzer (đồ án trên nền HDHunter)

## Dự án là gì
Công cụ **differential fuzzing** phát hiện HTTP Desync: gửi cùng 1 request (đã mutate) qua
**reverse-proxy** và thẳng vào **backend** qua raw TCP, so **State Tuple** 2 bên, áp "7 HDHunter Rules"
trong `diff_checker.py` để gắn cờ desync. Đây là bản **tự dựng lại phương pháp** của paper HDHunter
(USENIX Sec '25) — KHÔNG replicate 1:1 engine.

**Mục tiêu hiện tại (Phase 1):** nâng tool cho đo **đúng-paper trên 2 tầng** — (1) coverage gray-box
(Witcher-python), (2) internal-state 7-tuple thật (HttpParam shm) — rồi **đo lại baseline** TRƯỚC khi
bàn tích hợp LLM (Phase 2). Lý do LLM: xem `docs/IDEA_llm_integration.md`.

## Vị trí quan trọng
- **Docs kế hoạch (ĐỌC TRƯỚC KHI LÀM):**
  - `docs/PLAN_phase1_coverage.md` — plan Phase 1 chi tiết, các bước B0–B8.
  - `docs/REPO_UPSTREAM_NOTES.md` — repo gốc ở đâu, **bản đồ "mượn code gì ở đâu"**, **RULES đã chốt R1–R11**.
  - `docs/IDEA_llm_integration.md` — ý tưởng LLM (Phase 2), invariant, câu hỏi mở.
- **Artifact gốc HDHunter (untracked):** `/home/m321/doAn/AnToanMang/` (THƯ MỤC CHA, không phải `project/`).
  Mượn từ đây: `vendors/Witcher-python` (coverage), `hdhunter-rt` (HttpParam shm + C API),
  `fuzzing_targets/runtime/python/hdhunter.py` (ctypes wrapper), `hdhunter-replay` (replay).
- **Code tool:** `04_fuzzer_engine/{runner.py,diff_checker.py,wire_tap.py}`, `03_mutator/`,
  targets ở `02_targets/{nginx_gunicorn,ats_gevent,haproxy_flask,apache_tomcat}/`.
- **Kết quả cũ:** `05_analyzer/crash_reports_*/` (2718 report). Run mới (1337–1341) có coverage.py;
  run cũ (`baseline_pre`,`run2_pre`) không. Phân tích/triage: `05_analyzer/triage.py`.

## Quyết định đã chốt (chi tiết trong REPO_UPSTREAM_NOTES.md)
- **R1+A:** coverage = Witcher-python (bitmap `__AFL_SHM`, edge=`hash(f_lasti,f_lineno)%65536`), bỏ coverage.py.
- **R2:** tái lập TÍN HIỆU coverage, KHÔNG dùng engine QEMU-Nyx (vướng WSL2). Bitmap nạp vào corpus-growth của `runner.py`.
- **R9 (D2):** mỗi request log `cov_fingerprint` = hash tập edge request chạm (đo điểm mù).
- **R10 (D3):** phạm vi = `nginx_gunicorn` TRƯỚC → rồi `ats_gevent`/`haproxy_flask`. Hoãn proxy C & Tomcat.
- **R11:** Phase 1 làm LUÔN internal-state 7-tuple thật (Count/Consumed) — vá parser gunicorn, đọc HttpParam shm.

## Đang ở đâu / pick up từ đây
- **B0 ĐÃ XONG:** coverage.py thực ra chạy 96% trong scope (nginx_gunicorn request mode); "null 60%" là ảo
  do trộn report ngoài scope. Witcher cần vì faithfulness + 4% parser-reject + mịn hơn.
- **Witcher-python ĐÃ build OK** tại `/home/m321/doAn/AnToanMang/vendors/Witcher-python/python`
  (gcc, không cần QEMU). Coverage kích hoạt qua env `__AFL_SHM` + `__EXECUTION_PATH` (**= SysV shm ID,
  không phải path** — `shmat(atoi(...))`, xem R13) + `HDHUNTER_WITCHER_PYTHON_FILTER_PATH`. Bitmap = AFL bucket 65536.
- **✅ QUYẾT ĐỊNH ĐÃ CHỐT (R12):** internal-state = **phương án (ii) pure-Python** (ctypes→libc SysV shm),
  KHÔNG build Rust .so. Đã chứng minh end-to-end dưới Witcher (runner tạo shm → backend ghi → runner đọc lại đúng).
  Shim: `02_targets/nginx_gunicorn/backend/hdhunter.py` (drop-in API). Chi tiết R12–R14 trong REPO_UPSTREAM_NOTES.
- **✅ B2 XONG (đã chạy thật):** backend chạy gunicorn dưới Witcher-python trong Docker.
  Artifacts: `backend/Dockerfile.witcher` (FROM ubuntu:22.04, Witcher **bind-mount** /witcher), `docker-compose.witcher.yml`
  (**`ipc: host`** + bare-key passthrough `__AFL_SHM`/`__EXECUTION_PATH`/`__HTTP_PARAM`), `backend/witcher_filter.txt`,
  `backend/vendor_py/` (gunicorn 20.1 wheels + `ssl.py` stub vì Witcher thiếu `_ssl`).
  Lệnh: `docker compose -f docker-compose.yml -f docker-compose.witcher.yml up --build`.
  Giữ NGUYÊN `Dockerfile`/`docker-compose.yml` cũ (coverage.py) làm nhóm đối chứng A/B.
- **✅ B3 + B4b XONG (đã chạy thật end-to-end, có số):** chạy `runner.py --witcher`:
  - `04_fuzzer_engine/hdhunter_shm.py` — `WitcherShm` (tạo 3 SysV shm **0666** vì container userns-remap,
    reset/đọc bitmap+HttpParam) + `WitcherBackend` (context manager: tạo shm → `compose up` inject id →
    fuzz → `down`+cleanup). MAPSIZE=65536.
  - Runner đọc **out-of-band**: `reset → send proxy → đọc → reset → send direct → đọc`; ghi
    `cov_new_edges`/`cov_fingerprint`/`count_real`/`consumed_real`/`content_length_real`/`chunked_real`/`state_source`
    vào report (StateTuple field mới trong `diff_checker.py`, không phá rule cũ).
  - **B4b**: vá `vendor_py/gunicorn/http/{message,body}.py` (set CL/chunked + inc consumed/body) và `app.py`
    (init + mark_message_processed). Import `hdhunter` có guard → baseline coverage.py KHÔNG vỡ.
  - Đã xác minh: 1 request `CL:11` → 1902 edge thật + fingerprint; `count_real=1, consumed_real=[11]`.
    `__EXECUTION_PATH` BẮT BUỘC tạo (Witcher deref NULL → segfault nếu thiếu).
- **✅ B5+B6+B8 XONG (smoke-scale 48 case, có số):** `runner.py --witcher` thêm `--reports-dir` + `--trace-log`.
  Baseline `crash_reports_cov_b5/` (32 disc) + `05_analyzer/trace_cov_b5.jsonl`. Phân tích:
  `05_analyzer/analyze_cov_baseline.py`. Kết quả (xem `05_analyzer/BASELINE_cov_b5.md`):
  coverage 48/48 (hết null), **B6**: 21/32 disc được internal-state THẬT xác nhận / 11/32 là nhiễu wire,
  **B8**: 4 nhóm fingerprint mù (cùng edge, khác `consumed_real`/`CL` — vd consumed [5] vs [11]) → bằng chứng
  "coverage mù với number/length parsing", biện minh hướng LLM Phase 2.
- **Việc tiếp theo:** chạy B5 **rộng hơn** (nhiều mutation/seed) để B8 nhiều collision hơn; **B7** nhân sang
  `ats_gevent`/`haproxy_flask`. Phase 2 (LLM) chỉ sau khi điểm mù được xác nhận ở quy mô lớn hơn.

## Gotchas
- Bash tool **reset cwd về `project/` mỗi lệnh** — dùng đường dẫn tuyệt đối.
- HttpParam struct layout (cho phương án ii): `content_length[i64;10]`, `chunked_encoding[i8;10]`,
  `consumed_length[i64;10]`, `body_length[i64;10]`, `message_count i32`, `message_processed i8`,
  `status[i16;10]`, `order[i32;10]`. Reset (`clear`) trước mỗi request.
- Backend dùng gunicorn `--workers 1`; giữ 1 worker/1 thread/`--preload` cho tất định.
- Metric đánh giá: time-to-first-discrepancy + số loại discrepancy/ngân sách — KHÔNG phải coverage cuối.

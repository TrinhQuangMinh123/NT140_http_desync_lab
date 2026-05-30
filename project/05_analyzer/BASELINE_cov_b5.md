# Baseline `cov_b5` — paper-faithful run (coverage + internal-state)

**Cấu hình:** `runner.py --witcher` trên `nginx_gunicorn`, backend gunicorn chạy dưới
Witcher-python (coverage thật, bitmap 65536) + internal-state thật (HttpParam shm, parser gunicorn đã vá).
12 seed × (1 gốc + 3 mutation) = **48 logical cases**, `--random-seed 1337`.

Tái lập: `python3 04_fuzzer_engine/runner.py --witcher --mutations 3 --random-seed 1337
--reports-dir crash_reports_cov_b5 --trace-log 05_analyzer/trace_cov_b5.jsonl`
→ phân tích: `python3 05_analyzer/analyze_cov_baseline.py 05_analyzer/trace_cov_b5.jsonl`.

## Kết quả

| Mục | Số | Ý nghĩa |
|---|---|---|
| Coverage fingerprint có mặt | **48/48 (100%)** | Witcher thay coverage.py: hết "null". 19 fingerprint phân biệt. |
| Discrepancies | 32/48 | (reports trong `crash_reports_cov_b5/`) |
| **B6** — corroborated by REAL state | **21/32** | proxy-parse ≠ direct-parse: desync framing THẬT (internal-state xác nhận). |
| **B6** — response-observation-only | **11/32** | real state 2 bên giống → trigger rule-1/7 là *nhiễu wire*, cần replay. |
| **B8** — fingerprint mù (>1 real state) | **4 nhóm** | Cùng tập edge, KHÁC parse state. |

## B8 — bằng chứng "coverage mù" (deliverable học thuật)

4 nhóm `cov_fingerprint` trùng nhau nhưng state THẬT khác. Ví dụ rõ nhất:

- `fp 3d0577067c7a…` (cùng tập edge, cùng `chunked=True`) ⇒ **`consumed_real=[5]` vs `[11]`**.
  Backend đi **đúng cùng một đường code** nhưng nuốt số byte body KHÁC nhau.
- `fp 9a728f3ffdef…` ⇒ **`CL=[6],consumed=[6]` vs `CL=[11],consumed=[11]`**. Cùng path, khác Content-Length.

→ Coverage (edge bitmap) **không phân biệt** được hai input gây hệ quả parsing khác nhau khi
khác biệt nằm ở **giá trị số / độ dài** chứ không ở nhánh code. Đây chính là giả thuyết trung tâm
biện minh cho hướng LLM ở Phase 2 (`docs/IDEA_llm_integration.md`).

## Ghi chú phương pháp
- `consumed_real` (chunked) hiện xấp xỉ = body decoded (chưa tách byte framing) — B4b v1.
- proxy-side state = backend parse những gì nginx forward (nginx là C, chưa instrument).
- 48 case là smoke-scale; chạy rộng hơn (nhiều mutation / nhiều seed) sẽ cho B8 nhiều collision hơn.

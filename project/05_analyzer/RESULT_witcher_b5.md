# BÁO CÁO THỰC NGHIỆM — Bản Witcher (coverage thật + internal-state thật)

> Bản này **bổ sung** cho `result.md`. `result.md` là baseline cũ (935 report, 4 môi trường,
> chỉ quan sát response, coverage.py xấp xỉ, **không có parser-internal state**). Bản `cov_b5` đo lại
> **đúng-paper trên 2 tầng** (Witcher coverage + HttpParam 7-tuple thật) cho `nginx_gunicorn` request-side,
> qua đó **giải quyết đúng 2 hạn chế** mà `result.md` §10 tự liệt kê (parser-internal state + coverage).

## 0. Phạm vi số liệu

- Nguồn: `05_analyzer/crash_reports_cov_b5/` (32 report) + `05_analyzer/trace_cov_b5.jsonl` (48 dòng, mỗi
  logical case 1 dòng — gồm cả case KHÔNG discrepancy, để phân tích B8).
- Backend gunicorn chạy **dưới Witcher-python** (coverage interpreter-level, bitmap 65536) + **parser gunicorn
  đã vá** ghi HttpParam shm (Count/Consumed/Encoding/CL thật).
- Phạm vi: **chỉ `nginx_gunicorn`, request-side** (R10: làm chuẩn 1 cặp trước). Chưa nhân sang ats/haproxy/tomcat.

## 1. Cấu hình chạy

| Hạng mục | Giá trị |
|---|---|
| RNG seed | 1337 |
| Target | NGINX 1.25 → Gunicorn (Witcher-python 3.7.9, `--workers 1 --threads 1 --preload`) |
| Request seeds | 12 golden HTTP request seeds |
| Mutations/seed | 3 + 1 original = **48 logical cases** |
| Coverage | Witcher bitmap, reset/đọc out-of-band qua SysV shm mỗi request (R3) |
| Internal-state | HttpParam shm thật (B4b) |
| Snapshot/reset | shm zero trước mỗi request (thay cho restart-every) |

Tái lập:
```bash
python3 04_fuzzer_engine/runner.py --witcher --mutations 3 --random-seed 1337 \
  --reports-dir crash_reports_cov_b5 --trace-log 05_analyzer/trace_cov_b5.jsonl
python3 05_analyzer/analyze_cov_baseline.py 05_analyzer/trace_cov_b5.jsonl
```

## 2. Tổng quan & so sánh trực tiếp với baseline cũ

So sánh đúng cùng ô: **NGINX→Gunicorn, request-side, seed 1337**.

| Chỉ số | `result.md` (cũ, s1337) | `cov_b5` (Witcher) |
|---|---:|---:|
| Logical cases | 48 | 48 |
| Discrepancies | 28 (58.3%) | **32 (66.7%)** |
| Coverage fingerprint có mặt | ~0% trong archive (mostly null) | **48/48 (100%)** |
| Parser-internal state (Count/Consumed/CL thật) | ❌ không có | ✅ có (`count_real`/`consumed_real`/`chunked_real`/`content_length_real`) |
| Phân loại discrepancy theo state THẬT | ❌ không thể | ✅ B6 (xem §7) |
| Đo điểm mù coverage | ❌ không thể | ✅ B8 (xem §8) |

> Discrepancy tăng nhẹ (28→32) chủ yếu do coverage-directed corpus-growth nay chạy bằng coverage THẬT
> (+4 input sinh thêm trong run). Quan trọng hơn con số: lần đầu mỗi discrepancy có **bằng chứng nội bộ** đi kèm.

## 3. Rule frequency (đếm trên 48 case)

| Rule | Field | `cov_b5` | Hồ sơ cũ (NGINX req, 5 seed) |
|---|---|---:|---:|
| R1 | observed_response_count | 13 | 70 |
| R2 | observed_messages_parsed | 13 | 70 |
| R3 | status | 21 | 106 |
| R4 | transfer_encoding | 17 | 90 |
| R5 | content_length | 8 | 45 |
| R6 | body_length | 13 | 71 |
| R7 | raw_response_length | 30 | 157 |
| R8 | response_order | 24 | 119 |
| R9 | body_hash | 5 | 22 |

Hình dạng phân bố **giữ nguyên** (R7 nhiều nhất, rồi R8/R3) ⇒ pipeline Witcher tái lập đúng profile cũ,
chỉ khác là nay gắn thêm được state thật để lọc nhiễu (R7 chính là rule mà §5 báo cáo cũ cảnh báo "tín hiệu rộng").

## 4. Confidence

| Confidence | Reports |
|---|---:|
| high | 32 |
| low (partial_timeout) | 0 |

Toàn bộ 32 discrepancy đều high-confidence (single-worker + shm reset cho trạng thái sạch, không partial-read).

## 5. Mutation distribution (total / tạo discrepancy)

| Mutation | Total | → Discrepancy |
|---|---:|---:|
| original | 12 | 9 |
| sequence:remove | 6 | 6 |
| sequence:splice | 5 | 4 |
| byte:perturb_content_length | 4 | 0 |
| byte:obfuscate_unicode_encoding | 3 | 2 |
| byte:inject_smuggling_prefix | 2 | 2 |
| message:field_line_splice | 2 | 2 |
| message:trailer_section_replace | 2 | 2 |
| message:field_line_duplicate | 2 | 2 |
| byte:obfuscate_whitespace | 2 | 0 |
| byte:splice | 2 | 1 |
| (còn lại 1 mỗi loại) | 1 | 0–1 |

Giống `result.md` §9: `original` + `sequence:*` đóng góp nhiều nhất (golden seed vốn đã là edge-case HTTP/1.1).

## 6. [MỚI] Coverage faithfulness — giải quyết hạn chế cũ §10

| Chỉ số | Giá trị |
|---|---:|
| Case có `cov_fingerprint` thật | **48/48 (100%)** |
| Số fingerprint phân biệt | 19 |

`result.md` §10 ghi coverage chỉ là "approximation o backend Python bang coverage.py; archive mostly null".
Nay coverage là **edge bitmap interpreter-level y như paper**, 100% case có dữ liệu, mịn hơn line-coverage.

## 7. [MỚI] B6 — internal-state corroboration (lọc nhiễu rule-1/7)

Dùng state THẬT để hỏi: discrepancy này có được parse-state nội bộ xác nhận không?

| Phân loại | Số | % |
|---|---:|---:|
| Discrepancies | 32 | 100% |
| **Có divergence state THẬT** (proxy-parse ≠ direct-parse) | **21** | 65.6% |
| **Response-observation-only** (state thật 2 bên GIỐNG) | **11** | 34.4% |

→ Lần đầu định lượng được: **~34% discrepancy là nhiễu tầng-quan-sát** (đúng nỗi lo của `result.md` §5/§11
về R7 "cần replay"). 21 case còn lại là desync framing THẬT, có bằng chứng nội bộ.

## 8. [MỚI] B8 — điểm mù coverage (deliverable học thuật chính)

Gom case theo `cov_fingerprint` (direct); tìm nhóm cùng fingerprint nhưng **state THẬT khác**.

| Chỉ số | Giá trị |
|---|---:|
| Nhóm fingerprint có >1 state thật | **4** |

Ví dụ:
- `fp 3d0577…` (cùng edge, `chunked=True`) ⇒ `consumed_real=[5]` **vs** `[11]`.
- `fp 9a728f…` ⇒ `CL=[6],consumed=[6]` **vs** `CL=[11],consumed=[11]`.

⇒ Edge-coverage **mù** khi khác biệt nằm ở **giá trị số / độ dài** (không đổi nhánh code). Đây là bằng chứng
định lượng biện minh hướng LLM ở Phase 2 (`docs/IDEA_llm_integration.md`) — thứ `result.md` hoàn toàn chưa có.

## 9. Đối chiếu với "Hạn chế" của `result.md` §10

| Hạn chế cũ (result.md §10) | Trạng thái ở `cov_b5` |
|---|---|
| Parser-internal state — "Chưa có" | ✅ **Đã có**: HttpParam 7-tuple thật (Count/Consumed/Encoding/CL) |
| Coverage-directed feedback — coverage.py xấp xỉ | ✅ **Witcher bitmap thật**, 100% case, corpus-growth chạy bằng coverage thật |
| Snapshot executor — `docker restart` | ◑ thay bằng **shm zero/request** (cô lập coverage từng request) |
| Exploit confirmation | ◻ vẫn cần replay/PoC (ngoài phạm vi) |
| Combined edge map proxy+backend | ◻ mới backend (nginx là C, chưa instrument) |

## 10. Kết luận

1. `cov_b5` đo lại `nginx_gunicorn` request-side **đúng-paper trên 2 tầng**: 48 case, **32 discrepancy (66.7%)**,
   **coverage 100%** (so với mostly-null cũ).
2. Bổ khuyết đúng 2 hạn chế lớn nhất của `result.md`: parser-internal state + coverage thật.
3. **B6**: 21/32 discrepancy có bằng chứng nội bộ; **11/32 là nhiễu tầng-quan-sát** (định lượng được lần đầu).
4. **B8**: 4 nhóm "coverage mù" (cùng edge, khác consumed/CL) — bằng chứng cho hướng LLM Phase 2.
5. Đây là baseline ĐỐI CHỨNG (control) đúng-paper. Bước tiếp: chạy quy mô lớn hơn (nhiều mutation/seed) cho
   B8 nhiều collision hơn, rồi B7 nhân sang `ats_gevent`/`haproxy_flask`.

## 11. Artifacts

| Artifact | Nội dung |
|---|---|
| `05_analyzer/crash_reports_cov_b5/` | 32 discrepancy JSON (có `cov_fingerprint`, `count_real`, `consumed_real`, `state_source`) |
| `05_analyzer/trace_cov_b5.jsonl` | 48 dòng (mọi case) — input cho B6/B8 |
| `05_analyzer/analyze_cov_baseline.py` | Script B6/B8 (tái lập số §6–§8) |
| `05_analyzer/BASELINE_cov_b5.md` | Bản tóm tắt ngắn |

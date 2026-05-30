# PLAN — Phase 1: Chạy lại hệ thống mô phỏng paper với COVERAGE + INTERNAL-STATE ON

> Mục tiêu Phase 1: dựng lại **baseline dataset đúng-paper trên CẢ HAI tầng instrument** —
> (1) **coverage** Witcher-python (bitmap), (2) **internal-state 7-tuple** thật (HttpParam shm) —
> trên cặp backend Python, thu thập report theo schema hiện tại (+ field mới), để (a) đo lại
> kết quả CHÍNH XÁC như paper (hết nhiễu rule-1/rule-7), (b) làm nhóm ĐỐI CHỨNG cho A/B với LLM.
> **Phase 1 KHÔNG đụng tới LLM.** Tích hợp LLM bàn ở Phase 2 — chỉ sau khi đo lại baseline này.

---

## 0. Sự thật đã xác minh (đừng giả định lại)

| Sự thật | Bằng chứng |
|---|---|
| `coverage.py` ĐÃ được wire sẵn trong `app.py` (`coverage.Coverage(branch=True)`, `_snapshot_coverage()`, trả `cov_new_edges`) | `02_targets/nginx_gunicorn/backend/app.py` |
| `coverage==7.4.4` đã cài, gunicorn `--workers 1` | `backend/Dockerfile` |
| `diff_checker` đã ingest `cov_new_edges`; `runner.py` đã có logic corpus-growth theo coverage | `diff_checker.py:226`, `runner.py:651` |
| Run cũ (`baseline_pre`, `run2_pre`): **0%** report có coverage | đếm: 0/188, 0/236 |
| Run gần đây (`1337–1341`): coverage có số ở ~36% TOÀN BỘ 935 report | đếm |
| **[B0 đính chính]** "null ~60%" là ẢO — do trộn report NGOÀI scope: response-mode (376), Tomcat-Java (147, coverage.py Python không áp dụng), cặp khác (247) | B0 phân loại |
| **Trong ĐÚNG phạm vi Phase 1 (`nginx_gunicorn`, request mode): coverage.py đã chạy 96%** (160/165). 5 ca null = 4×status-400 + 1×status-0 = parser-reject thật | B0 |
| `Witcher-python` build & chạy được, coverage thật không cần QEMU; đọc bitmap qua shm out-of-band nên bắt edge parser kể cả khi app.py không chạy | đã build & demo (memory `hdhunter-graybox-feasible`) |

**Hệ quả B0:** coverage.py KHÔNG hỏng trong scope (96%). Witcher-python cần vì **3 lý do** (không phải "sửa pipeline"):
(1) **faithfulness** y chang paper; (2) **lấy lại 4% parser-reject** (status 400 — đúng ca desync thú vị); (3) **mịn hơn** (bytecode-edge vs line) → đo điểm mù B8 chuẩn hơn.

---

## 1. QUYẾT ĐỊNH CẦN CHỐT (chờ xác nhận)

### D1 — Cơ chế coverage  ✅ ĐÃ CHỐT: Witcher-python (y chang bài báo)
Dùng **Witcher-python** — instrument tầng interpreter, edge = `hash(f_lasti, f_lineno) % 65536`
ghi vào AFL bitmap qua `__AFL_SHM`. **Bỏ `coverage.py`.** Đây đúng cơ chế đo coverage của paper.

**Hệ quả của "y chang" cần nắm:**
1. Ta chỉ sao chép **TÍN HIỆU coverage** (bitmap interpreter), KHÔNG sao chép engine QEMU-Nyx/LibAFL.
   Bitmap này được nạp vào logic corpus-growth sẵn có trong `runner.py` thay cho LibAFL.
2. **Tách edge từng request**: process gunicorn chạy dài → bitmap tích luỹ. Phải **zero bitmap `__AFL_SHM`
   trước mỗi request** (runner điều khiển qua shm) để cô lập coverage của riêng request đó —
   thay cho cơ chế snapshot-reset của Nyx mà ta không có.
3. **Filter include-list**: tái dùng cấu hình lọc của paper (dòng `+/-module.func`) để scope coverage
   đúng vùng xử lý HTTP (`+gunicorn`, `+app`, `+http`), tránh nhiễu nội bộ interpreter.
4. **Backend Docker đổi**: image phải build/nhúng Witcher-python (CPython 3.7.9, đã xác minh build OK
   trên Ubuntu 22.04/gcc 11) + pip gunicorn vào interpreter đó; chạy gunicorn dưới nó.

### D2 — Coverage FINGERPRINT mỗi request  ⚠️ QUAN TRỌNG NHẤT
Hiện chỉ log `cov_new_edges` = **một con số đếm**. Con số này **KHÔNG đủ** để kiểm giả thuyết
trung tâm ("coverage mù: hai payload gây desync KHÁC nhau nhưng đi qua CÙNG tập edge").
→ Đề xuất **bắt buộc thêm**: `cov_fingerprint` = sha256 của **tập edge mà CHÍNH request này chạm**
(không phải delta tích lũy). Có nó mới so được "khác desync nhưng cùng coverage".
Khuyến nghị: **CÓ**.

### D3 — Phạm vi target Phase 1
- **(a)** Chỉ `nginx_gunicorn` trước → xong mới `ats_gevent` (cùng backend Python). Khuyến nghị.
- **(b)** Cả hai cặp Python ngay.
- **(c)** Thử luôn proxy C (cần `clang -fsanitize-coverage`). → đề nghị HOÃN sang phase sau.

### D4 — Mặc định triển khai (sẽ làm trừ khi bạn phản đối)
- Pin gunicorn **1 worker, 1 thread, `--preload`** để accumulator coverage ổn định, tất định.
- Chuẩn hoá ngữ nghĩa reset coverage **theo từng request** (đo edge của riêng request, tách khỏi nhiễu startup).
- Giữ nguyên seeds / số mutation / `--repeat` / random-seed như run `1337–1341` để so sánh công bằng.

---

## 2. Schema report — thay đổi đề xuất (tối thiểu, không phá cũ)

Giữ nguyên mọi field hiện có. Thêm vào cả `proxy_state` và `direct_state`:

| Field mới | Ý nghĩa | Phụ thuộc |
|---|---|---|
| `cov_fingerprint` | sha256 tập edge request này chạm (hash ổn định) | D2 |
| `cov_total_edges` | tổng edge tích luỹ (app đã tính, chỉ chưa lưu) | — |
| `cov_source` | `"witcher-python"` (truy xuất nguồn — đã chốt D1) | D1 |
| `cov_edges_sample` *(tuỳ chọn)* | danh sách edge thô, CHỈ lưu cho ca phân kỳ, để soi tay | D2 |
| `state_source` | `"httpparam-shm"` (state thật) vs `"wire-derived"` (đoán cũ) — đánh dấu để so | internal-state |
| `count_real`, `consumed_real[]` | **Count & Consumed THẬT** từ HttpParam shm (thay vì đoán từ wire-length) | internal-state |

`cov_new_edges` giữ nguyên nghĩa cũ (đếm edge mới so accumulator). Các field `message_count`/
`consumed_length` cũ (đoán từ wire) **giữ lại để so sánh** với `count_real`/`consumed_real` → định lượng nhiễu cũ.

---

## 3. Các bước thực thi

- **B0 — Chẩn đoán & ghi nhận** lý do null 60% (đo: bao nhiêu null là do parser-reject vs backend lỗi). 1 con số để báo cáo.
- **B1 — Chốt D1/D2/D3** (mục 1).
- **B2 — Backend chạy dưới Witcher-python**: sửa `backend/Dockerfile` build/nhúng Witcher-python +
  cài gunicorn vào interpreter đó; chạy gunicorn dưới nó. Set `__AFL_SHM`, `__EXECUTION_PATH`,
  `HDHUNTER_WITCHER_PYTHON_FILTER_PATH` (filter `+gunicorn`,`+app`,`+http`).
- **B3 — Đọc bitmap + fingerprint**: app/harness đọc bitmap `__AFL_SHM` sau mỗi request → `cov_new_edges`
  (đếm edge mới) + `cov_fingerprint` (hash tập edge request này chạm); lưu qua `diff_checker` + `runner.save_report`.
- **B4 — Tất định**: pin gunicorn 1 worker/1 thread/`--preload`; **zero bitmap trước mỗi request** để cô lập coverage.
- **B4b — INTERNAL-STATE (tầng thứ 2, phần khó):**
  - Build `hdhunter-rt` thành `libhdhunter_rt_no_edge.so` (cargo, feature `no_edge`) → cung cấp shm `HttpParam` + C API.
  - Backend `import hdhunter` (ctypes wrapper `runtime/python/hdhunter.py`), gọi `hdhunter_init()`.
  - **Vá parser gunicorn** (`gunicorn/http/message.py`, `body.py`) chèn lời gọi tại đúng điểm:
    `set_content_length` (khi parse CL), `set_chunked_encoding` (khi thấy TE chunked),
    `inc_consumed_length`/`inc_body_length` (khi nuốt byte body), `mark_message_processed` (khi xong 1 message).
  - Runner đọc `HttpParam` shm sau mỗi request → `count_real`, `consumed_real[]` (thật, không đoán từ wire).
- **B5 — Chạy lại fuzzer** trên `nginx_gunicorn`, cùng tham số run `134x`; output `crash_reports_cov_<id>/`.
- **B6 — Kiểm chứng vận hành**: coverage non-null TĂNG; sanity fingerprint; **đối chiếu `consumed_real` vs `consumed_length` cũ** → đo lại bao nhiêu false-positive rule-1/rule-7 biến mất.
- **B7 — Lặp lại** cho `ats_gevent` (rồi `haproxy_flask`) — R10.
- **B8 — Phân tích điểm mù** (deliverable học thuật): đếm số ca **(desync state THẬT khác nhau) ∧ (cov_fingerprint giống hệt)**. Bằng chứng định lượng cho "coverage mù với number-parsing" — biện minh (hoặc bác bỏ) ý tưởng LLM ở Phase 2.

---

## 4. Ngoài phạm vi Phase 1 (để sau)

- Coverage proxy C (nginx/haproxy/ats) qua `clang -fsanitize-coverage`.
- Internal-state phía **proxy C** (chỉ làm phía backend Python trong Phase 1).
- Backend **Java/Tomcat** (cần `Witcher-java`).
- **Tích hợp LLM** (Phase 2) — chỉ làm sau khi đo lại baseline đúng-paper (coverage + internal-state) và B8 xác nhận điểm mù.

---

## 5. Deliverable Phase 1

1. Bộ `crash_reports_cov_<id>/` có **coverage đáng tin (Witcher) + internal-state thật (HttpParam)** + fingerprint.
2. Báo cáo: (a) bao nhiêu false-positive rule-1/rule-7 cũ biến mất khi dùng Count/Consumed thật;
   (b) "bằng chứng điểm mù coverage": số ca desync-thật-khác / coverage-giống.
3. Baseline đúng-paper làm nhóm đối chứng cho A/B với LLM ở Phase 2.

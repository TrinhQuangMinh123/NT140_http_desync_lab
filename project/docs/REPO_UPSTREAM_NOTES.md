# GHI CHÚ — Repo gốc HDHunter & quy tắc dự án

> File tra cứu nhanh: **mã nguồn gốc của paper ở đâu**, **mượn phần nào ở đâu** khi thiếu,
> và **các rule đã chốt** trong quá trình bàn. Cập nhật khi có quyết định mới.

---

## 1. Nguồn upstream (mã gốc của tác giả)

| Nguồn | Địa chỉ |
|---|---|
| Paper | USENIX Security '25 — "HDHunter: coverage-directed differential testing for HTTP Desync". Bản local: `usenixsecurity25-mu.docx` (+ `docx_output.txt`) |
| GitHub | `https://github.com/mukeran/HDHunter` |
| Zenodo (archive) | `https://zenodo.org/records/14557764` |
| Hướng dẫn build gốc | `/home/m321/doAn/AnToanMang/BUILDING.md` |

**QUAN TRỌNG — bản gốc ĐÃ tải về sẵn, nằm UNTRACKED tại git root `/home/m321/doAn/AnToanMang/`**
(KHÔNG phải trong `project/`). Đã xác minh là code chính chủ, build & chạy được
(xem memory `hdhunter-graybox-feasible`). Cần gì cứ mượn thẳng từ đây.

---

## 2. Bản đồ "mượn code gì ở đâu" (tại `/home/m321/doAn/AnToanMang/`)

| Thư mục/Component | Là gì | Mượn khi cần |
|---|---|---|
| `vendors/Witcher-python/` | **CPython 3.7.9 đã vá** — coverage tầng interpreter (AFL bitmap qua `__AFL_SHM`). Build OK bằng gcc. | **Cốt lõi Phase 1** — backend chạy dưới đây để đo coverage y chang paper |
| `vendors/Witcher-java/`, `vendors/hdhunter-ruby3/` | Interpreter vá cho Java (Tomcat) / Ruby | Khi mở rộng sang Tomcat |
| `hdhunter-rt/src/lib.rs` | Runtime: setup shm coverage (`__AFL_SHM`) + state (`HttpParam` qua `PARAM_SHMEM`); chế độ `HDHUNTER_TRACE` ghi trace ra file | Tham chiếu cách đọc bitmap / lấy internal-state 7-tuple |
| `fuzzing_targets/runtime/{python,c,java,ruby}/` | API mỏng để app báo state về (vd `hdhunter.py`, `hdhunter_api.h`) | Khi cần internal-state thật (Consumed/Count) |
| `fuzzing_targets/targets/` | Cấu hình target gốc: `apache`, `tomcat`, `apache-resp`… (gồm filter include-list) | **Mượn filter include-list** để scope coverage đúng vùng HTTP |
| `hdhunter/src/{mutators,observers,feedbacks,input}` | Lõi fuzzer (LibAFL): mutator, observer coverage, feedback | Tham chiếu thiết kế mutator/feedback; KHÔNG port nguyên |
| `hdhunter-cc/` | Wrapper compiler (SanitizerCoverage) cho target C | Khi làm coverage proxy C (nginx/haproxy/ats) — phase sau |
| `hdhunter-replay/src/` | **Replay tất định** một input vào target | Dựng "validation environment" / PoC |
| `hdhunter-helper/src/` | Convert seed, dedup input | Mượn `convert-input`, dedup |
| `hdhunter-runner/src/` | Vòng chạy fuzzer chính (ghép Nyx) | Tham chiếu luồng; ta dùng `runner.py` riêng |
| `vendors/{QEMU-Nyx,libnyx,libafl_nyx,packer}` | **Engine snapshot QEMU-Nyx** | ❌ KHÔNG dùng (không dựng được trên WSL2) — chỉ tham khảo |
| `example_seeds/`, `tokens.json` | Seed + từ điển token gốc | Đã/đang kế thừa làm input |

---

## 3. RULES đã chốt

### R1 — Cơ chế coverage = Witcher-python (y chang paper) ✅ (chọn phương án A)
Đo coverage bằng **Witcher-python** (interpreter-level, edge = `hash(f_lasti,f_lineno)%65536`
→ AFL bitmap qua `__AFL_SHM`). **Bỏ `coverage.py`.** [B0 đính chính: coverage.py đã chạy 96% trong scope;
lý do đổi là (1) faithfulness y chang paper, (2) lấy lại 4% parser-reject, (3) mịn hơn — KHÔNG phải sửa pipeline hỏng.]

### R11 — Internal-state 7-tuple THẬT vào Phase 1 ✅
Phase 1 làm CẢ tầng internal-state, không chỉ coverage. Dùng `HttpParam` shm + API
`runtime/python/hdhunter.py` (build `libhdhunter_rt_no_edge.so`), **vá parser gunicorn** để lấy
**Count & Consumed THẬT** (thay vì đoán từ `raw_response_length` → nguồn nhiễu false-positive rule-1/rule-7).
Lý do: "đo chuẩn như paper" cần cả 2 tầng; phần làm tool sai nhiều nhất (nhiễu) nằm ở internal-state, không phải coverage.
⚠️ Đây là phần KHÓ nhất Phase 1 (chèn code vào parser gunicorn) — nhưng R10 chỉ vá 1 parser trước.

### R2 — Tái lập TÍN HIỆU, không tái lập ENGINE ✅
Sao chép đúng *cách đo* coverage của paper, NHƯNG **không** dùng QEMU-Nyx/LibAFL (rào cản thật trên
WSL2). Bitmap được nạp vào logic corpus-growth có sẵn trong `runner.py`. Phải nói rõ điều này khi báo cáo.

### R3 — Cô lập coverage theo request ✅
Process gunicorn chạy dài → bitmap tích luỹ. **Zero bitmap `__AFL_SHM` trước mỗi request** (runner điều
khiển qua shm) để lấy edge của riêng request — thay cho snapshot-reset của Nyx.

### R4 — Tất định / single-process ✅
gunicorn **1 worker, 1 thread, `--preload`**; giữ nguyên seeds / số mutation / `--repeat` / random-seed
như run `1337–1341` để A/B công bằng.

### R5 — Filter include-list ✅
Tái dùng cấu hình lọc của paper (dòng `+/-module.func`), scope coverage đúng vùng HTTP
(`+gunicorn`, `+app`, `+http`), tránh nhiễu nội bộ interpreter.

### R6 — LLM nằm NGOÀI hot loop (rule cho Phase 2) ✅
Mọi tích hợp LLM phải ở ngoài vòng fuzz nóng để giữ exe/s. Chi tiết: xem `IDEA_llm_integration.md`.

### R7 — Phase 1 KHÔNG đụng LLM ✅
Phase 1 chỉ dựng coverage + baseline + đo điểm mù. LLM là Phase 2, chỉ làm nếu điểm mù được xác nhận.

### R8 — Metric đánh giá ✅
Cái cần đo: **time-to-first-discrepancy** và **số loại discrepancy tìm được trong ngân sách cố định**
(Bảng 2 paper) — KHÔNG phải coverage cuối cùng.

### R9 — Log `cov_fingerprint` mỗi request ✅ (chốt D2)
Mỗi request lưu `cov_fingerprint` = `hash(sorted(các bucket bitmap nonzero request này chạm))`,
tính từ **cùng một lần đọc bitmap** với `cov_new_edges` → gần như miễn phí. Là công cụ đo điểm mù ở B8
(đếm ca: desync khác nhau ∧ fingerprint giống hệt). Paper không có sẵn — phần thêm của ta.

### R10 — Phạm vi Phase 1 ✅ (chốt D3 = a)
Làm chuẩn **`nginx_gunicorn` trước** (chạy thông toàn bộ pipeline coverage Witcher), rồi nhân bản
sang `ats_gevent` và `haproxy_flask`. **Hoãn** proxy C (clang sancov) và Tomcat (Witcher-java) sang phase sau.

### R12 — Internal-state HttpParam = **PHƯƠNG ÁN (ii) pure-Python**, KHÔNG build Rust .so ✅ (giải "câu hỏi mở")
Tái hiện `HttpParam` 7-tuple + 5 hàm instrument **bằng Python thuần (ctypes → libc `shmget`/`shmat`)**,
ghi vào **SysV shm**. **Không** build `libhdhunter_rt_no_edge.so` (khỏi cài Rust, khỏi cần mạng cho
cargo, khỏi dựng cả workspace libafl, và **khỏi tái hiện định dạng shm của libafl_bolts** mà phía Rust dùng).
- File: `02_targets/nginx_gunicorn/backend/hdhunter.py` — **drop-in** đúng tên API của
  `fuzzing_targets/runtime/python/hdhunter.py` (parser patch viết y hệt dù dùng .so hay shim).
- Struct `#[repr(C)]` = **328 byte** (đã xác minh ctypes khớp byte-for-byte); logic roll-over
  `message_processed→message_count` port nguyên từ `hdhunter-rt/src/lib.rs`.
- **Đã CHỨNG MINH end-to-end** dưới chính Witcher-python: runner (host) tạo SysV shm → backend
  Witcher attach qua env `__HTTP_PARAM` → ghi 7-tuple → runner đọc lại đúng (test PASS).
- Nếu `__HTTP_PARAM` chưa set → shim chạy **no-op** (backend vẫn chạy độc lập).

### R13 — Phát hiện về cơ chế shm của Witcher (ảnh hưởng kiến trúc) ✅
Đọc `vendors/Witcher-python/Python/ceval.c`:
1. `__AFL_SHM` và `__EXECUTION_PATH` là **SysV shm ID** (`shmat(atoi(getenv(...)))`), KHÔNG phải path/mmap.
   → runner phải `shmget` tạo segment rồi truyền **id** qua env.
2. **`__EXECUTION_PATH`** giữ sẵn rolling-hash `*31 + edge` của tập edge đã thăm → gần như **miễn phí cho
   `cov_fingerprint` (D2/R9)**; chỉ cần zero `visited_edges`/segment trước mỗi request để tách theo request.
3. **BẮT BUỘC `ipc: host`** cho container backend: shm tạo ở host chỉ attach được trong container nếu
   chung IPC namespace. Dùng chung cho cả bitmap coverage lẫn HttpParam.
4. **Bẫy chí mạng:** env shm để **rỗng `""` cũng bị coi là "đã set"** → `shmat(0)` → con trỏ -1 →
   **segfault (exit 139)** ngay edge đầu. Trong compose phải dùng **bare-key passthrough** (`- __AFL_SHM`),
   KHÔNG dùng `${__AFL_SHM:-}` (cho ra `""`). Khi chưa fuzz thì 3 biến này phải UNSET.
5. **Filter include-list** (`HDHUNTER_WITCHER_PYTHON_FILTER_PATH`): mỗi dòng `<+/->prefix`,
   prefix-match (strncmp) lên `module[.class].func`, **default-deny**, dòng khớp ĐẦU TIÊN thắng.
   File ta dùng: `+gunicorn.http`, `+gunicorn.workers.sync`, `+app`.

### R14 — Witcher-python build THIẾU `_ssl` → dùng ssl-stub, KHÔNG rebuild interpreter ✅
CPython 3.7.9 của Witcher build không có module `_ssl` → gunicorn (`import ssl` ở config.py) chết import.
Backend chạy **HTTP trần** (sau nginx) nên không cần TLS thật. Giải pháp: **`vendor_py/ssl.py` stub**
(chỉ vài hằng `PROTOCOL_*`, `CERT_NONE`, `SSLError`) đứng trước stdlib trên PYTHONPATH. Rẻ hơn rebuild
interpreter (3.7.9 vs OpenSSL 3.0 dễ vỡ) và không động vào tầng instrument coverage.
- gunicorn = **20.1.0** (wheel pure-python, tương thích 3.7), giải nén sẵn vào `backend/vendor_py/` vì
  Witcher không pip-qua-HTTPS được (thiếu `_ssl`); tải bằng `pip download` của python hệ thống (có ssl).

# BÁO CÁO THỰC NGHIỆM — v3 (faithful + framing-aware, exhaustive scale)

> **Quan hệ với v2:** `docs/resultv2.md` đo faithful request-side nhưng bộ đo internal-state còn **thô**:
> chỉ 4 đại lượng (count/consumed/CL/chunked) và `consumed == body` (KHÔNG đếm byte framing của chunked).
> v3 **không đổi phương pháp** — chỉ **nâng độ trung thực của bộ ĐO** và **mở rộng quy mô**:
> (1) parser core ghi thêm `body_length` **tách khỏi** `consumed` (consumed = byte wire kể cả framing
> chunk-size line/CRLF/trailer; body = payload decode) → mở **trục framing `consumed − body`**;
> (2) quy mô 719 → **14,614 case**.
>
> **Mọi số trong file verify trực tiếp từ `05_analyzer/trace_full_v3_*.jsonl`** (24 file, 14,614 dòng).
> Tái lập: `bash 05_analyzer/run_witcher_v3.sh` → phân tích bằng `05_analyzer/analyze_witcher_full.py`
> (lọc glob `trace_full_v3_*`).

---

## 0. Phạm vi & cấu hình

| Hạng mục | Giá trị |
|---|---|
| Env faithful | NGINX→Gunicorn, HAProxy→Gunicorn, ATS→Gunicorn (đều backend gunicorn-under-Witcher) |
| RNG seeds | 1337–1344 (**8 seed**) |
| Golden request seeds | 12 |
| Mutations/seed | **50** + 1 original = 51 variant → 612 logical case/(env,seed) |
| Tổng | 3 × 8 × 612 ≈ **14,614 case** (vài case skip do timeout) |
| Coverage | Witcher bitmap 65536, reset/đọc out-of-band mỗi request |
| Internal-state | HttpParam shm — **5 đại lượng framing-relevant** từ core parser (xem §8) |
| Backend | gunicorn 1 worker / 1 thread / `--preload` (tất định) |

---

## 1. So sánh trực tiếp v2 ↔ v3 (điểm cốt: profile lõi KHÔNG đổi, deliverable MẠNH hơn)

| Chỉ số | v2 (faithful thô) | v3 (faithful + framing) |
|---|---:|---:|
| Logical case | 719 | **14,614** (≈20×) |
| Discrepancy hit-rate | 56.1% | **57.9%** |
| Coverage present | 99.9% | **99.97%** |
| B8 blind groups (tổng 3 env) | 15 | **51** |
| └ **structural** | **0** | **36** |
| └ numeric | 15 | 15 |

**Đọc bảng:** hit-rate gần như y nguyên ở 20× quy mô ⇒ nâng bộ đo + scale-up **không bóp méo** profile
differential (phép kiểm tính toàn vẹn). Lớp **numeric giữ đúng 15** (5/env) — cái mới xuất hiện đúng là
lớp **structural** (36), không phải nhiễu do đổi cách đo.

---

## 2. Discrepancy theo env × seed

| Env | 1337 | 1338 | 1339 | 1340 | 1341 | 1342 | 1343 | 1344 | Tổng | Hit% |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| NGINX → Gunicorn | 429 | 420 | 408 | 414 | 401 | 418 | 424 | 410 | **3324** | 68.2 |
| HAProxy → Gunicorn | 322 | 307 | 329 | 316 | 313 | 293 | 304 | 313 | **2497** | 51.2 |
| ATS → Gunicorn | 334 | 328 | 340 | 335 | 316 | 336 | 330 | 321 | **2640** | 54.3 |
| **Tổng** | | | | | | | | | **8461** | **57.9** |

Hit-rate cực ổn định giữa 8 seed (độ lệch nhỏ) ⇒ con số là tính chất hệ thống, không phải may rủi RNG.

---

## 3. B6 — internal-state corroboration (lọc nhiễu tầng-quan-sát)

| Env | Disc | Có divergence state THẬT | % |
|---|---:|---:|---:|
| NGINX → Gunicorn | 3324 | 2191 | **65.9%** |
| HAProxy → Gunicorn | 2497 | 1049 | **42.0%** |
| ATS → Gunicorn | 2640 | 1093 | **41.4%** |

Thứ tự **NGINX > HAProxy > ATS** giữ NGUYÊN như v2 (63 > 34 > 26) — kết luận định tính "NGINX desync
framing thật nhiều nhất" tái lập ở quy mô lớn (giá trị nhích lên do state v3 giàu chiều hơn để đối chiếu).

---

## 4. B8 — điểm mù coverage, **phân loại structural vs numeric** (deliverable chính)

Gom case theo `cov_fingerprint` (direct), tìm nhóm **cùng tập edge** nhưng **state THẬT khác**.
`classify_blind`: **structural** = message-count / chunked-mode / **framing-overhead (consumed−body)**
khác → coverage-blind VÀ vượt ngoài number-format; **numeric** = chỉ khác magnitude CL/consumed/body.

| Env | distinct fp | B8 blind | **structural** | numeric | max state/1 fp |
|---|---:|---:|---:|---:|---:|
| NGINX → Gunicorn | 106 | 17 | **12** | 5 | **20** |
| HAProxy → Gunicorn | ~107 | 18 | **13** | 5 | 19 |
| ATS → Gunicorn | ~104 | 16 | **11** | 5 | 19 |
| **Tổng** | | **51** | **36** | 15 | |

**Bằng chứng tái lập:** đúng các fingerprint `fe1db789b1…`, `b8cf7df07d…` là structural blind group
**trên cả 3 proxy** ⇒ điểm mù là tính chất của **parser backend + tín hiệu edge-coverage dùng chung**,
không phải artifact của một proxy. Ví dụ:

- `fp fe1db789b1` (cùng edge, `chunked=True`): `consumed=[21] body=[11]` **vs** `consumed=[24] body=[5]`.
  Cùng đường code, app thấy body khác nhau VÀ framing wire khác nhau — coverage hoàn toàn mù.
- `fp 96923d68f49e` (nginx): **20 parse-state khác nhau cùng MỘT fingerprint**, `consumed` chạy 32→110,
  body chỉ 5/11 → 20 cách đóng khung chunk khác nhau, edge-coverage không phân biệt nổi cái nào.

→ v2 (consumed=body) **không thể** thấy lớp này; v3 cho thấy nó **lớn và tái lập 3 proxy**.

---

## 5. ⚙️ Ghi chú PHƯƠNG PHÁP (để báo cáo chính xác, tránh overclaim)

- **Lấy từ core parser, KHÔNG phải từ wire:** parser gunicorn đã vá ghi thẳng **5 đại lượng
  framing-relevant** vào HttpParam shm: `message_count`, `content_length`, `chunked_encoding`,
  `consumed_length` (v3: kể cả byte framing), `body_length` (v3: tách khỏi consumed). Runner đọc out-of-band.
- **KHÔNG phải "7-tuple đầy đủ từ core":** struct có thêm `status`/`order` nhưng **parser request-side
  KHÔNG sinh** (status là khái niệm response; order là wire-observation do `diff_checker` lấy từ đường truyền).
  Chúng nằm trong struct nhưng **luôn 0** request-side — surface verbatim cho đủ, không phải tín hiệu thật.
- **2 field `wire_*` cũ giữ lại** làm đối chứng audit nhiễu (B6), không bị bỏ.
- **Vì sao nâng bộ đo TRƯỚC khi gắn LLM (confound control):** nếu ablation LLM chạy trên bộ đo cũ
  (mù framing) mà kết quả không tăng, **không phân biệt được** "LLM vô dụng" với "bộ đo quá thô để thấy
  cái LLM tạo ra". Faithful trước ⇒ kết quả ablation **diễn giải được**. (Việc này KHÔNG tự làm LLM thắng.)

---

## 6. ⚠️ HẠN CHẾ (nêu thẳng)

- **Chỉ faithful request-side.** Response-side desync vẫn **black-box**: đối tượng đo là response-parser của
  **proxy C** (chưa instrument), origin là `FakeUpstream` socket thường → không có shm coverage/HttpParam
  để lấy từ core; harness chỉ so byte wire. Đúng phạm vi code mà paper cấp sẵn (request-side). **Giữ như cũ**,
  vai trò breadth-demo, không đóng góp cho luận điểm điểm-mù.
- **"Structural" CHƯA chứng minh "cần LLM".** 36 nhóm structural đều là biến thể **framing chunk** — một
  **dictionary chunk-framing tĩnh** vẫn có thể chạm tới. B8 chỉ chứng minh **điểm mù vượt-number-format là
  thật và lớn**; câu "LLM > dictionary" là việc của **ablation 3 nhánh** (coverage-only · +dict · +LLM).
- **Thiếu cặp Apache→Tomcat** (Java, chặn bởi Witcher-java build) — như v2 §9. ATS đổi backend gevent→gunicorn.
- Không claim khớp số tuyệt đối Bảng 2 paper (target/engine/quy mô khác).

---

## 7. Kết luận

1. **Profile lõi bảo toàn ở 20× quy mô** (hit 57.9% ≈ v2 56.1%, B6 thứ tự NGINX>HAProxy>ATS giữ nguyên)
   ⇒ refactor + scale-up đáng tin, không bóp méo.
2. **B8 nâng cấp deliverable:** v2 chỉ thấy 15 nhóm numeric (yếu cho luận điểm); v3 lộ **36 nhóm structural**
   (vượt number-format), **tái lập trên cả 3 proxy**, một fingerprint gánh tới **20 parse-state**.
3. **Điều kiện tiên quyết của Phase 2 ĐẠT:** điểm mù coverage vượt-number-format là thật & lớn — thứ v2 để ngỏ.
4. **Còn mở (ablation 3 nhánh quyết):** liệu LLM đóng điểm mù tốt hơn một dictionary framing tĩnh — luận điểm
   *đích thực LLM-shaped* = phân kỳ **đặc thù theo cặp proxy×backend** mà từ điển generic không nhắm tới.

---

## 8. Artifacts

| Artifact | Nội dung |
|---|---|
| `05_analyzer/trace_full_v3_*.jsonl` | 24 file (3 env × 8 seed), 14,614 case — input B6/B8 |
| `05_analyzer/crash_reports_cov_v3_*/` | report discrepancy có cov_fingerprint + full HttpParam |
| `05_analyzer/run_witcher_v3.sh` | driver tái lập |
| `05_analyzer/analyze_witcher_full.py` | aggregator (real_state +body, classify_blind structural/numeric) |
| `docs/resultv2.md` | bản faithful thô trước framing-split (đối chứng) |

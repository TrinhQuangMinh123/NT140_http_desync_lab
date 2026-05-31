# BÁO CÁO THỰC NGHIỆM v3 — SỐ LIỆU CHI TIẾT (faithful + framing-aware)

> Bản chi tiết theo đúng cấu trúc `resultv1.md`, nhưng trên pipeline **faithful request-side**
> (Witcher coverage bitmap + HttpParam internal-state từ core parser) và bộ đo **framing-aware**
> (v3: `consumed` kể byte framing ≠ `body` payload). Bản tóm tắt để nộp: `docs/resultv3.md`.
> Mọi số verify trực tiếp từ `05_analyzer/trace_full_v3_*.jsonl` (24 file, 14,614 dòng) +
> `05_analyzer/crash_reports_cov_v3_*/`.

## 0. Phạm vi số liệu

- Nguồn: `trace_full_v3_<env>_<seed>.jsonl` (3 env × 8 seed = 24 file) + `crash_reports_cov_v3_<env>/`.
- **14,614 logical case request-side** (3 env × 8 seed × 12 golden × ~51 variant; vài case skip do timeout).
- KHÔNG có response-side trong v3 (run request-side; response-side giữ black-box v1, xem §10).

## 1. Cấu hình chạy

| Hạng mục | Giá trị |
|---|---|
| RNG seeds | 1337, 1338, 1339, 1340, 1341, 1342, 1343, 1344 (**8 seed**) |
| Target env (faithful) | NGINX→Gunicorn, HAProxy→Gunicorn, ATS→Gunicorn (đều backend gunicorn-under-Witcher) |
| Request seeds | 12 golden HTTP request seed |
| Mutations/seed | **50** + 1 original = 51 variant → 612 case/(env,seed) |
| Tổng expected | 3 × 8 × 612 = 14,688 (thực 14,614, vài case timeout) |
| Coverage | Witcher bitmap 65536, reset/đọc out-of-band mỗi request |
| Internal-state | HttpParam shm — 5 đại lượng từ core parser (count/CL/chunked/consumed/body), `consumed≠body` |
| Snapshot/reset | shm zero trước mỗi request |
| Backend | gunicorn 1 worker / 1 thread / `--preload` |

Reproduce: `bash 05_analyzer/run_witcher_v3.sh` → `05_analyzer/analyze_witcher_full.py` (glob `trace_full_v3_*`).

## 2. Tổng quan kết quả & so sánh v1/v2/v3

| Chỉ số | v1 (black-box, 4 env) | v2 (faithful thô, 3 env) | **v3 (faithful + framing)** |
|---|---:|---:|---:|
| Logical case (request-side) | 960 | 719 | **14,614** |
| Discrepancy | 559 | 403 | **8,461** |
| Hit rate | 58.2% | 56.1% | **57.9%** |
| Coverage present | ~0% (coverage.py) | 99.9% | **99.97%** |
| Internal-state | ❌ | 4 field (consumed=body) | **5 field, consumed≠body** |
| B8 blind groups | ❌ | 15 (0 structural) | **51 (36 structural)** |

Hit-rate 57.9% sát v1/v2 ⇒ profile differential **bảo toàn** dù 20× quy mô + đổi bộ đo. *Hit rate là tỉ lệ
case tạo discrepancy, KHÔNG phải tỉ lệ lỗ hổng* — discrepancy chỉ là tín hiệu cần replay/PoC.

## 3. Request-side results theo env × seed

| Môi trường | s1337 | s1338 | s1339 | s1340 | s1341 | s1342 | s1343 | s1344 | Tổng | Mean | Stddev | Hit% |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| NGINX 1.25 → Gunicorn | 429 | 420 | 408 | 414 | 401 | 418 | 424 | 410 | **3324** | 415.5 | ±8.51 | 68.2 |
| HAProxy 2.9 → Gunicorn | 322 | 307 | 329 | 316 | 313 | 293 | 304 | 313 | **2497** | 312.1 | ±10.35 | 51.2 |
| ATS → Gunicorn | 334 | 328 | 340 | 335 | 316 | 336 | 330 | 321 | **2640** | 330.0 | ±7.57 | 54.3 |
| **Tổng** | 1085 | 1055 | 1077 | 1065 | 1030 | 1047 | 1058 | 1044 | **8461** | | | **57.9** |

Nhận xét: stddev nhỏ trên cả 8 seed ⇒ con số là tính chất hệ thống, không phải may rủi RNG. Thứ tự
NGINX > ATS > HAProxy về hit-rate giữ ổn định.

## 4. Rule frequency

| Môi trường | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | R9 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| NGINX → Gunicorn | 1324 | 1324 | 2285 | 1818 | 957 | 1488 | 3171 | 2489 | 333 |
| HAProxy → Gunicorn | 1054 | 1054 | 655 | 533 | 918 | 560 | 2096 | 1264 | 844 |
| ATS → Gunicorn | 704 | 704 | 911 | 464 | 942 | 529 | 1579 | 1236 | 643 |
| **OVERALL** | 3082 | 3082 | 3851 | 2815 | 2817 | 2577 | **6846** | **4989** | 1820 |

(R1=`observed_response_count`, R2=`observed_messages_parsed`, R3=`status`, R4=`transfer_encoding`,
R5=`content_length`, R6=`body_length`, R7=`raw_response_length`, R8=`response_order`, R9=`body_hash`.)

Nhận xét: R7 (raw length) nhiều nhất — tín hiệu rộng, cần replay (nay được B6 §7 lọc bằng state thật).
R8 (order oracle) mạnh trên NGINX (2489) — khớp v1/v2. R1≡R2 (count≡processed) theo thiết kế.

## 5. Mutation distribution (total / → discrepancy, gộp 3 env)

| Mutation | Total | → Disc | %disc |
|---|---:|---:|---:|
| sequence:splice | 2388 | 1651 | 69.1 |
| sequence:remove | 2359 | 1102 | 46.7 |
| message:trailer_section_replace | 911 | 495 | 54.3 |
| message:node_typed_swap | 867 | 457 | 52.7 |
| message:field_line_duplicate | 784 | 556 | 70.9 |
| message:field_line_splice | 759 | 495 | 65.2 |
| message:field_line_remove | 714 | 441 | 61.8 |
| message:node_token_replace | 693 | 396 | 57.1 |
| byte:perturb_content_length | 641 | 362 | 56.5 |
| byte:obfuscate_unicode_encoding | 580 | 302 | 52.1 |
| byte:splice | 573 | 307 | 53.6 |
| byte:obfuscate_transfer_encoding | 536 | 259 | 48.3 |
| byte:inject_smuggling_prefix | 517 | 326 | 63.1 |
| byte:byte_insert | 517 | 247 | 47.8 |
| byte:byte_remove | 508 | 304 | 59.8 |
| byte:byte_duplicate | 492 | 282 | 57.3 |
| byte:obfuscate_whitespace | 487 | 319 | 65.5 |
| original | 288 | 160 | 55.6 |

`sequence:*` + `field_line_*` đóng góp disc nhiều nhất; `original` cũng cho 55.6% vì golden seed vốn là
edge-case HTTP/1.1 mơ hồ (dup CL, TE.CL, CL.TE, trailer, pipelining).

## 6. Confidence & stability (partial_timeout)

| Môi trường | Reports | High | Low | %Low |
|---|---:|---:|---:|---:|
| NGINX → Gunicorn | 3324 | 3283 | 41 | 1.2 |
| HAProxy → Gunicorn | 2497 | 2299 | 198 | 7.9 |
| ATS → Gunicorn | 2640 | 1684 | 956 | 36.2 |

Low = `partial_timeout=True` (R7 bị suppress, tín hiệu còn lại vẫn nên replay). ATS cao nhất do keep-alive/
timeout dài hơn — khớp đúng quan sát v1.

## 7. [FAITHFUL] B6 — internal-state corroboration (lọc nhiễu tầng-quan-sát)

Dùng HttpParam THẬT 2 phía hỏi: discrepancy có được parse-state nội bộ xác nhận (proxy-parse ≠ direct-parse)?

| Môi trường | Disc | Có divergence state THẬT | % | Response-observation-only |
|---|---:|---:|---:|---:|
| NGINX → Gunicorn | 3324 | 2191 | **65.9%** | 1133 |
| HAProxy → Gunicorn | 2497 | 1049 | **42.0%** | 1448 |
| ATS → Gunicorn | 2640 | 1094 | **41.4%** | 1546 |

Thứ tự **NGINX > HAProxy > ATS** giữ NGUYÊN như v2 (63>34>26%) ⇒ "NGINX desync framing thật nhiều nhất"
tái lập ở 20× quy mô. (Giá trị nhích lên do state v3 giàu chiều hơn để đối chiếu.)

## 8. [FAITHFUL — deliverable chính] B8 — điểm mù coverage, phân loại structural vs numeric

Gom case theo `cov_fingerprint` (direct), tìm nhóm **cùng tập edge** nhưng **state THẬT khác**.
**structural** = message-count / chunked-mode / framing-overhead (consumed−body) khác (coverage-blind VÀ
vượt number-format); **numeric** = chỉ khác magnitude CL/consumed/body.

| Môi trường | B8 blind | **structural** | numeric | max state/1 fp |
|---|---:|---:|---:|---:|
| NGINX → Gunicorn | 17 | **12** | 5 | **20** |
| HAProxy → Gunicorn | 18 | **13** | 5 | 19 |
| ATS → Gunicorn | 16 | **11** | 5 | 19 |
| **Tổng** | **51** | **36** | **15** | |

**Tái lập 3 proxy:** cùng fingerprint `fe1db789b1…`, `b8cf7df07d…` là structural blind group trên cả 3 env
⇒ điểm mù là tính chất của parser backend + edge-coverage dùng chung, không phải artifact 1 env. Ví dụ:

- `fp fe1db789b1` (cùng edge, chunked): `consumed=[21] body=[11]` **vs** `consumed=[24] body=[5]`.
- `fp 96923d68f49e` (nginx): **20 parse-state khác nhau / 1 fingerprint**, consumed 32→110, body chỉ 5/11.

v2 (consumed=body) không thấy được lớp này; v3 cho thấy nó lớn & tái lập 3 proxy.

## 9. Diversity

| Môi trường | distinct cov_fingerprint | distinct real-state |
|---|---:|---:|
| NGINX → Gunicorn | 106 | 65 |
| HAProxy → Gunicorn | 105 | 62 |
| ATS → Gunicorn | 98 | 58 |

`distinct real-state > ` số nhóm blind cho thấy đa số fingerprint ánh xạ 1-1 với state; chỉ một phần nhỏ
(51 nhóm) là many-to-one — chính các nhóm đó là điểm mù.

## 10. Hạn chế so với HDHunter paper / so với v1

| Hạn chế | Trạng thái v3 |
|---|---|
| Parser-internal state | ✅ 5 field từ core (v2 có 4, consumed=body); `status`/`order` parser req không sinh (xem ghi chú) |
| Coverage-directed feedback | ✅ Witcher bitmap thật 99.97% (v1 chỉ coverage.py xấp xỉ) |
| Response-side | ◻ **giữ black-box** (origin FakeUpstream, response-parser proxy C chưa instrument) — breadth demo |
| Cặp Apache→Tomcat (env thứ 4) | ◻ thiếu (Java, chặn bởi Witcher-java build) — giới hạn công cụ |
| Snapshot executor | ◑ shm zero/request (không QEMU snapshot) |
| Exploit confirmation | ◻ discrepancy là candidate, cần replay/PoC |
| "structural" ⇒ cần LLM? | ◻ **CHƯA** — 36 structural đều là framing-chunk, dictionary chunk-framing vẫn chạm; việc của ablation 3 nhánh |

> **Ghi chú đo lường (tránh overclaim):** parser core ghi 5 đại lượng framing-relevant; `status`/`order`
> nằm trong struct nhưng request-side luôn 0 (không phải "7-tuple đầy đủ từ core"). 2 field `wire_*` cũ giữ
> làm đối chứng B6.

## 11. Kết luận

1. **14,614 case · 8461 disc (57.9%)** — profile lõi bảo toàn so v1/v2 (58.2/56.1%) dù 20× quy mô + đổi bộ đo.
2. **B6**: desync framing THẬT theo proxy NGINX 65.9% > HAProxy 42% > ATS 41% — thứ tự như v2.
3. **B8 (chính)**: 51 blind group, **36 structural** (v2=0), **tái lập 3 proxy**, 1 fp gánh tới 20 parse-state
   ⇒ điểm mù coverage vượt-number-format là **thật & lớn** → điều kiện tiên quyết Phase 2 ĐẠT.
4. Còn mở: "LLM > dictionary" chưa chứng minh — việc của **ablation 3 nhánh** (coverage-only · +dict · +LLM);
   luận điểm đích-thực-LLM = phân kỳ đặc thù **cặp proxy×backend**.

## 12. Artifacts

| Artifact | Nội dung |
|---|---|
| `05_analyzer/trace_full_v3_*.jsonl` | 24 file (3 env × 8 seed), 14,614 case |
| `05_analyzer/crash_reports_cov_v3_<env>/` | 3324 / 2497 / 2640 report (nginx / haproxy / ats) |
| `05_analyzer/run_witcher_v3.sh` | driver tái lập |
| `05_analyzer/analyze_witcher_full.py` | aggregator (real_state +body, classify_blind) |
| `docs/resultv3.md` | bản tóm tắt để nộp |
| `resultv1.md` / `docs/resultv2.md` | đối chứng black-box / faithful-thô |

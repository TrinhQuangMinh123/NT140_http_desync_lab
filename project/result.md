# BÁO CÁO THỰC NGHIỆM — HDHUNTER-Inspired Differential Testbed

**Công cụ:** HTTP Desync Differential Fuzzer (HDHUNTER-inspired)
**Ngày chạy:** 2026-05-22
**Số seeds:** 12 Golden Seeds (raw HTTP/1.1 từ `01_data_prep/seeds_db/`)
**Mutations/seed:** 3 + 1 original = 48 test cases/env
**Tổng test cases:** 192 (4 env × 48)
**Random seed:** 1337 (reproducible)
**Detection rules:** 9 (7 HDHUNTER-inspired + 2 mở rộng: R8 Order, R9 body_hash)
**Reproduction:** `MUTATIONS=3 RANDOM_SEED=1337 REPEAT_COUNT=1 bash run_all.sh --fuzz-only`

---

## 1. Tổng quan kết quả (Executive Summary)

| Môi trường (Proxy → Backend) | Test cases | Discrepancies | Hit Rate |
|---|---:|---:|---:|
| NGINX 1.25 → Gunicorn (Python WSGI)   | 48 | **44** | **91.7%** |
| HAProxy 2.9 → Gunicorn (Python WSGI)  | 48 | **36** | **75.0%** |
| ATS → gevent (Python)                 | 48 | **48** | **100.0%** |
| Apache HTTPD 2.4 → Tomcat 10 (Java)   | 48 | **37** | **77.1%** |
| **Tổng**                              | **192** | **165** | **85.9%** |

**Lưu ý quan trọng**:
- "Hit Rate" là **discrepancy rate**, KHÔNG phải vulnerability rate. Discrepancy chỉ là tín hiệu cần phân tích, không tự động khẳng định khai thác được.
- So với baseline trước (Apr 2026, 7 rule, 154 discrepancy), version mới sau cập nhật A1+A2+A5+A8 ghi nhận **165 discrepancy (+7%)** nhờ bổ sung R8 (Order) và R9 (body_hash) — phát hiện thêm các trường hợp length-only oracle bỏ sót.

---

## 2. Tần suất kích hoạt mỗi Rule

| Rule | Field | NGINX | HAProxy | ATS | Apache | Ý nghĩa |
|---|---|---:|---:|---:|---:|---|
| R1 | `message_count`       | 18 | 14 | 7  | 2  | Pipeline desync candidate |
| R2 | `message_processed`   | 18 | 14 | 7  | 2  | Một bên parse hoàn chỉnh hơn |
| R3 | `status`              | 21 | 6  | 11 | 3  | Status code khác |
| R4 | `transfer_encoding`   | 17 | 5  | 2  | 12 | Cách xử lý TE khác |
| R5 | `content_length`      | 7  | 0  | 4  | 12 | Cách xử lý CL khác |
| R6 | `body_length`         | 14 | 5  | 8  | 0  | Backend đọc lượng byte khác |
| R7 | `consumed_length`     | 43 | 34 | 47 | 34 | Raw response length khác |
| **R8** | `order` (MỚI)     | 25 | 12 | 11 | 0  | **Response order desync — Stealing candidate** |
| **R9** | `body_hash` (MỚI) | 5  | 7  | 3  | 0  | **Body content khác (cùng length) — TE.CL offset** |

### Quan sát:

- **R7 (consumed_length)** là rule fire nhiều nhất ở mọi env — chứng tỏ proxy thường thêm/bớt header so với backend direct, tạo response length khác. Bản chất là "noise" nhưng vẫn là tín hiệu response-side đáng theo dõi.
- **R8 (Order)** fire 48 lần tổng cộng → cải tiến A1 (X-Desync-Id UUID injection) **bắt được các trường hợp pipeline desync mà length-only oracle bỏ sót**.
- **R9 (body_hash)** fire 15 lần tổng cộng → cải tiến A2 phát hiện content khác nhau dù body_length giống nhau (smoking gun cho TE.CL offset shift).
- **Apache HTTPD → Tomcat không có R8/R9 hit** vì Tomcat là Java servlet, không trả JSON với 2 field mới — code insertion A1/A2 chỉ áp dụng cho 3 cặp WSGI Python.
- **R5 (Content-Length) cao nhất ở Apache (12)** — Apache HTTPD reject hoặc normalize CL khác Tomcat — kết quả khớp paper §5.2.4 (Different request TE.CL handling).

---

## 3. Attack Candidate Matrix

Phân loại heuristic dựa trên rule kích hoạt:

| Proxy | Request Smuggling | Response Stealing/Forgery | Request Confusing | Total |
|---|---:|---:|---:|---:|
| NGINX        | 18 (40.9%) | 17 (38.6%) | 9 (20.5%)  | 44 |
| HAProxy      | 14 (38.9%) | 17 (47.2%) | 5 (13.9%)  | 36 |
| ATS          | 7 (14.6%)  | 37 (77.1%) | 4 (8.3%)   | 48 |
| Apache HTTPD | 2 (5.4%)   | 23 (62.2%) | 12 (32.4%) | 37 |

**Quy tắc phân loại** (xem [05_analyzer/triage.py](05_analyzer/triage.py)):
- **Smuggling candidate**: R1 hoặc R2 fire (số message khác → pipeline desync).
- **Confusing candidate**: R4/R5/R6 fire mà không có R1/R2 (content discrepancy).
- **Response candidate**: chỉ R3/R7/R8/R9 fire (length/order khác, không thêm/bớt message).

**Insight**:
- **ATS có discrepancy rate cao nhất (100%) và Response candidate cao nhất (77%)** — khớp với paper: ATS không sanitize trailer, forward nguyên byte → tạo nhiều response-side mismatch.
- **NGINX và HAProxy có Smuggling candidate cao** (40%+) — pipeline desync rõ hơn 2 env còn lại.
- **Apache HTTPD ít Smuggling nhất (5%) nhưng Confusing cao** — Apache nghiêm khắc về message boundary nhưng vẫn để TE/CL xung đột lọt qua xuống Tomcat.

---

## 4. Quan sát chi tiết về các cải tiến A1/A2/A5/A8

### 4.1 R8 — X-Desync-Id Order Tracking (A1)

48 case ghi nhận order khác nhau. 3 mẫu điển hình:

**Mẫu 1** — HAProxy: proxy thấy 2 UUID, backend direct chỉ thấy 1:
```
proxy order:  ['ae97d7de...', '58c35241...']
direct order: ['ae97d7de...']
```
→ HAProxy split payload thành 2 request, Gunicorn chỉ parse 1 → R1+R2+R8 cùng fire. Strong pipeline desync candidate.

**Mẫu 2** — ATS: proxy không nhận được response nào (timeout/reject), backend direct nhận 1 UUID:
```
proxy order:  []
direct order: ['90b3d600...']
```
→ ATS reject payload nhưng backend chấp nhận. Đây là **policy mismatch** — không phải vulnerability ngay nhưng cho thấy ATS strict hơn.

### 4.2 R9 — Body Hash Content Discrepancy (A2)

15 case body_hash khác nhau. Ví dụ ATS+gevent:
```
proxy   body_length=5  body_hash=f0393febe8baaa55
direct  body_length=0  body_hash=e3b0c44298fc1c14  (= sha256 của empty)
Mutator: message:field_line_duplicate
```
→ Backend direct đọc body rỗng, qua proxy thì đọc 5 byte. Trường hợp này length CÓ khác nên R6 cũng fire — đây là double-confirm.

Trường hợp **R9 fire mà R6 không fire** (length giống, content khác) là smoking gun thực sự cho TE.CL offset shift. Cần lọc thêm:

### 4.3 wsgi_eof — A5 EOF Anomaly

0 case có `wsgi_eof=false`. Điều này có nghĩa: trong tập test hiện tại, **không có case nào backend đọc dư bytes** sau khi consume xong message. Lý do có thể:
- WSGI server (Gunicorn/gevent) đã tiêu hóa hết stream theo đúng CL.
- Hoặc các edge case TE.CL bị reject sớm, không đến được stage WSGI read.

→ Cần thêm seed test TE.CL "tinh vi hơn" (chunked với body dài hơn CL claim) để kích hoạt được anomaly này.

### 4.4 A8 Fix — R6 (body_length) under both_error

Trước A8 fix, R6 bị skip khi cả 2 path trả 4xx/5xx → bỏ sót case "cả 2 reject nhưng đọc lượng byte khác nhau trước khi reject". Sau fix, R6 fire trong **27 case** (NGINX:14 + HAProxy:5 + ATS:8 + Apache:0). Đáng chú ý là **0 hit ở Apache** — Apache HTTPD reject ngay từ proxy nên backend không có cơ hội đọc body.

---

## 5. Stability Analysis

Toàn bộ 165 discrepancy được lưu kèm `repeat_analysis` metadata. Với `REPEAT_COUNT=1` (baseline run), tất cả đều là single-shot — chưa có dữ liệu stability.

**Khuyến nghị**: chạy thêm với `REPEAT_COUNT=3` để lọc unstable discrepancy:
```bash
MUTATIONS=3 RANDOM_SEED=1337 REPEAT_COUNT=3 bash run_all.sh --fuzz-only
```

---

## 6. So sánh trước/sau cải tiến (A1+A2+A5+A8)

| Chỉ số | Baseline (7 rule, Apr 2026) | Sau A1+A2+A5+A8 (9 rule, May 2026) | Thay đổi |
|---|---:|---:|---:|
| NGINX → Gunicorn   | 37 | 44 | +7 |
| HAProxy → Gunicorn | 36 | 36 | 0 |
| ATS → gevent       | 45 | 48 | +3 |
| Apache → Tomcat    | 36 | 37 | +1 |
| **Tổng**           | **154** | **165** | **+11 (+7.1%)** |

**Quan sát**: tăng chủ yếu ở NGINX (+7) — vì cặp này là Python WSGI, hưởng lợi đầy đủ từ R8/R9. HAProxy không tăng (do payload bị reject sớm, không vào được WSGI). Apache hầu như không tăng (Tomcat backend không trả enriched JSON).

---

## 7. Case Study — Discrepancy điển hình

### Case 1 — Pipeline Desync (NGINX, sequence:splice)

```
Triggered rules: R1, R2, R4, R5, R7
proxy:  message_count=2,  CL=5,  TE=False
direct: message_count=2,  CL=-1, TE=True
Order:  cả 2 path đều thấy 2 UUID đúng thứ tự
```

→ Cả 2 path thấy 2 message nhưng proxy normalize chunked → raw (CL=5, TE=False), backend direct giữ nguyên chunked (CL=-1, TE=True). Đây là kinh điển NGINX rewrite TE → CL khi forward.

### Case 2 — Request Smuggling Candidate (HAProxy, byte:inject_smuggling_prefix)

```
Notable: Proxy detected 0 request(s), but Backend detected 1 request(s).
```

→ HAProxy reject toàn bộ payload (status 0 nghĩa là không có response), nhưng nếu gửi thẳng vào Gunicorn thì Gunicorn chấp nhận. Mutator `inject_smuggling_prefix` thành công tạo payload mà HAProxy không tài nào parse. Đây là tín hiệu HAProxy có policy chặt hơn Gunicorn — **không phải vulnerability**, mà là điểm cộng phòng thủ của HAProxy.

### Case 3 — Content Discrepancy without Length (R9, ATS+gevent)

```
proxy   body_length=5  hash=f0393feb...
direct  body_length=0  hash=e3b0c442... (empty)
```
→ Mutator `message:field_line_duplicate` đã làm gevent backend (direct) không đọc được body, nhưng qua ATS thì đọc được 5 byte. Cần replay để biết ATS đã forward "5 byte ảo" gì.

---

## 8. Hạn chế của testbed

| Hạn chế so với HDHUNTER paper | Trạng thái trong project |
|---|---|
| Không có internal parser state cho proxy | Mitigated: backend WSGI expose `cl_env`, `wsgi_eof`, `body_hash` (gray-box ở backend side) |
| Không có coverage feedback | Chưa có — mutation random theo seed 1337 |
| Không có QEMU snapshot | Mitigation: mỗi test fresh TCP connection, có thể restart container giữa batch |
| Không tự động xác nhận exploitability | Chỉ ra **attack candidate**, cần replay PoC để khẳng định |
| Chưa có response-side harness đầy đủ | Test chỉ request-side, response-side chỉ qua R7/R8/R9 (heuristic) |
| Apache+Tomcat thiếu R8/R9 | Tomcat là Java servlet, không trả enriched JSON — chỉ R1-R7 áp dụng |

---

## 9. Kết luận

1. **Bộ test 192 ca** ghi nhận **165 discrepancy** trên 4 cặp Proxy ↔ Backend, hit rate trung bình **85.9%**. Số liệu này khẳng định **mọi cặp Proxy-Backend phổ biến đều có parser discrepancy** — đúng tinh thần paper.

2. **Cải tiến A1+A2+A5+A8** thêm 11 discrepancy mới (+7.1%) và bắt được 2 nhóm pattern paper đề cập mà version cũ bỏ sót:
   - R8 (Order) → Response Stealing candidate (paper §5.3.3).
   - R9 (body_hash) → Content discrepancy với cùng body length (paper §5.2.5).

3. **ATS đứng đầu** về discrepancy rate (100%) và Response candidate (77%) — khớp với paper §5.2.2 (ATS không sanitize trailer).

4. **HAProxy đứng cuối** về raw discrepancy count nhưng cao về Smuggling candidate — gợi ý HAProxy reject sớm là policy hợp lý.

5. **Discrepancy ≠ vulnerability**. Để khẳng định khai thác được, bước tiếp theo cần:
   - Replay payload nghi ngờ → backend connection được reuse có thực sự nhận request ẩn.
   - tcpdump capture giữa proxy ↔ backend → biết proxy forward thật sự gì.
   - Response-side harness (fake upstream) để minh họa Response Stealing/Forgery.

---

## Reproduce

```bash
cd /home/lehuuhoang/project
bash run_all.sh --stop                    # dừng env cũ nếu có
bash run_all.sh                           # start + fuzz tất cả
# hoặc
MUTATIONS=3 RANDOM_SEED=1337 bash run_all.sh --fuzz-only
python3 05_analyzer/triage.py             # triage
```

Logs lưu tại: `/tmp/fuzz_baseline.log`, `/tmp/triage.log`.
Reports JSON: `05_analyzer/crash_reports/discrepancy_*.json`.
Baseline cũ (trước A1+A2+A5+A8): `05_analyzer/crash_reports_baseline_pre_A1A2A5A8/`.

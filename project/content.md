# Slide Content — HTTP Desync Differential Fuzzer
> Nội dung slide bảo vệ đồ án. Tổng ~15 slides.
> Người làm slide: đọc từng section, lấy bullet points, số liệu và hình minh họa được chỉ định.

---

## SLIDE 1 — Trang Bìa

**Tiêu đề chính:**
> HTTP Desync Differential Fuzzer
> Phát hiện lỗ hổng HTTP Request Smuggling bằng phương pháp Kiểm thử Sai lệch

**Ghi chú:**
- Background: tối, có hình terminal đang chạy hoặc network traffic
- Logo trường + mã môn học

---

## SLIDE 2 — Vấn Đề: HTTP Request Smuggling

**Nội dung:**
- Hệ thống web hiện đại thường có kiến trúc: `Client → Reverse Proxy → Backend Server`
- Proxy và Backend **đều phải parse HTTP** — nhưng chúng được viết bằng các ngôn ngữ và tuân thủ RFC ở mức độ khác nhau
- Khi cùng một gói tin HTTP được hai bên hiểu **theo cách khác nhau** → **HTTP Desync** (Sai lệch đồng bộ)

**Hậu quả thực tế:**
- Kẻ tấn công chèn ẩn một request vào giữa luồng HTTP → **vượt qua WAF, chiếm session người dùng khác, đọc dữ liệu nhạy cảm**
- Các CVE liên quan: **CVE-2019-9516** (Nginx), **CVE-2022-26377** (Apache), báo cáo HackerOne của Portswigger Research

**Hình minh họa:** Vẽ sơ đồ 3 hộp:
```
Client ──→ [ Reverse Proxy ] ──→ [ Backend ]
                  ↑ thấy 1 req        ↑ thấy 2 req  ← Desync!
```

---

## SLIDE 3 — Tại Sao Khó Phát Hiện?

**Vấn đề của công cụ hiện tại:**
- Burp Suite / ZAP chỉ test theo danh sách case **đã biết trước** (manually crafted)
- Không thể tự khám phá lỗi **mới** trên các cặp Proxy/Backend chưa từng được test
- Không có công cụ mã nguồn mở nào tự động hóa việc test **nhiều cặp hệ thống cùng lúc**

**Giải pháp:** Cần một **Fuzzer tự động** có phương pháp luận học thuật rõ ràng

---

## SLIDE 4 — Nền Tảng: HDHunter Paper

**Bài báo gốc:**
> *"HDHUNTER: Hunting HTTP Desync Vulnerabilities with Differential Fuzzing"*
> Đăng tại hội nghị bảo mật quốc tế uy tín (USENIX Security / IEEE S&P)

**4 tiêu chí phân loại lỗi của HDHunter:**
| Tiêu chí | Nội dung |
|----------|----------|
| **Taxonomy** | Hình thái Desync: số lượng / nội dung / thứ tự message |
| **Discrepancies** | Sai lệch kỹ thuật: Non-standard parsing, TE.CL conflict… |
| **Attacks** | Kịch bản tấn công: Smuggling, Confusing, Response Forgery |
| **Insights** | Nguyên nhân gốc: Lỗi ngôn ngữ, RFC không chuẩn, chuyển đổi protocol |

**Dự án này:** Tái hiện phương pháp luận của HDHunter bằng Python + Docker — accessible, extensible và chạy được trên mọi máy.

---

## SLIDE 5 — Differential Testing

**Định nghĩa:**
> Gửi **cùng một input** đến hai hệ thống khác nhau → so sánh output → nếu output khác nhau → bug nằm ở đây

**Sơ đồ (vẽ bằng PowerPoint):**
```
Mutated Payload
      │
      ├──── raw TCP ──→  Reverse Proxy (Nginx) ──→ State Tuple A
      │
      └──── raw TCP ──→  Backend (Gunicorn)   ──→ State Tuple B
                                                         │
                                              [ diff_checker ] ← 7 Rules
                                                         │
                                              Discrepancy Report .json
```

**Tại sao dùng Raw TCP?**
- Các thư viện HTTP Python (requests, httpx) tự sửa header trước khi gửi → che giấu lỗi
- Raw socket truyền byte-for-byte chính xác như payload đột biến

---

## SLIDE 6 — Kiến Trúc Hệ Thống (6 Phases)

**Vẽ dạng timeline ngang với 6 ô:**

| Phase | Module | Chức năng |
|-------|--------|-----------|
| 01 | `01_data_prep/collector.py` | Sinh 12 Golden Seeds đại diện 12 edge-case HTTP |
| 02 | `02_targets/` | 4 cặp Proxy/Backend chạy Docker |
| 03 | `03_mutator/` | 14 mutation strategies (3 tầng) |
| 04 | `04_fuzzer_engine/runner.py` | Raw TCP fuzzing + 7-rule diff checker |
| 05 | `05_analyzer/triage.py` | Phân loại theo HDHunter Taxonomy |
| 06 | `06_exploits_poc/` | PoC exploit từ payload nguy hiểm nhất |
| 07 | `07_mini_test_suite/` | Demo độc lập cho thuyết trình |

---

## SLIDE 7 — Golden Seed Corpus (12 Seeds)

**Lý do thiết kế 12 Seeds thay vì tạo ngẫu nhiên:**
> "Coverage > Volume" — 12 seeds nhắm đúng 12 ngóc ngách của RFC HTTP/1.1 hiệu quả hơn 1000 seeds ngẫu nhiên

**Bảng 12 seeds (2 cột):**

| Seed | Edge Case nhắm tới |
|------|--------------------|
| seed_01 | Standard GET (baseline) |
| seed_02 | POST + Content-Length |
| seed_03 | POST + Transfer-Encoding: chunked |
| seed_04 | **TE Line Folding** (`TE:\r\n chunked`) |
| seed_05 | **Absolute URI** (`GET http://host/`) |
| seed_06 | **Duplicate Content-Length** |
| seed_07 | **CL.TE Conflict** (classic smuggling) |
| seed_08 | **TE.CL Conflict** (classic smuggling reversed) |
| seed_09 | Chunk Extension (`5;ext=evil`) |
| seed_10 | Trailer Headers (sau body) |
| seed_11 | **Pipelining** (2 requests trên 1 TCP) |
| seed_12 | Padded CL (`Content-Length: 00011`) |

---

## SLIDE 8 — Mutation Engine (14 Mutators)

**3 tầng đột biến:**

**Tầng 1 — Sequence Level (2)**
- `sequence_splice` : Ghép 2 seed thành pipeline
- `sequence_remove` : Cắt bỏ một phần pipeline

**Tầng 2 — Message Level (4)**
- `field_line_duplicate` : Nhân đôi một header
- `field_line_remove` : Xóa ngẫu nhiên một header
- `node_token_replace` : Đổi token (`chunked` → `identity`)
- `node_typed_swap` : Hoán đổi 2 header với nhau

**Tầng 3 — Byte Level (8) — gồm 3 Advanced ⚡**
- `byte_insert / remove / duplicate` : Đột biến bit-level
- `obfuscate_transfer_encoding` : `\tchunked`, `CHunKed`...
- `perturb_content_length` : `-1`, `999`, `0`
- ⚡ `obfuscate_whitespace` : Chèn `\x0B`, `\x00` vào tên header
- ⚡ `obfuscate_unicode_encoding` : `10` → `１０`, `0xa`
- ⚡ `inject_smuggling_prefix` : HTTP/2.0 preface giả (`PRI * HTTP/2.0`)

**Số test cases:**
```
Total = Seeds × (1 + Mutations)
      = 12 × (1 + 3) = 48 cases  [lần chạy thực nghiệm]
```

---

## SLIDE 9 — Ma Trận Môi Trường (4 Targets)

**Bảng:**

| # | Reverse Proxy | Backend | Proxy Port | Backend Port |
|---|---------------|---------|------------|--------------|
| 1 | **Nginx 1.25** | Gunicorn (WSGI) | 8888 | 9001 |
| 2 | **HAProxy 2.9** | Gunicorn (WSGI) | 8890 | 9003 |
| 3 | **Apache Traffic Server** | Gevent (Python) | 8889 | 9002 |
| 4 | **Apache HTTPD 2.4** | Apache Tomcat 10 | 8891 | 9004 |

**Điểm quan trọng:**
- Tất cả proxy được cấu hình **tắt header normalization** → để lộ hành vi parse thật
- Tất cả backend cùng trả về **State Tuple JSON** → so sánh được đồng nhất

---

## SLIDE 10 — Demo / Kết Quả Chạy

**Screenshot terminal (chụp sẵn, dán vào slide):**

```
============================================================
  HTTP Desync Differential Fuzzer
  Target   → nginx_gunicorn
  Proxy    → 127.0.0.1:8888
  Backend  → 127.0.0.1:9001
  Seeds    = 12  |  Mutations/seed = 3
============================================================

🔴 DISCREPANCY [seed 08  mut 05  [byte:inject_smuggling_prefix]]
  Field              Proxy (Nginx)    Backend (Direct)
  ──────────────────────────────────────────────────
  1. status          400              0
  2. message_count   1                0             ← DESYNC!
  3. message_processed 1              0             ← DESYNC!
  7. consumed_length 309              391

  Triggered Rules:
    Rule 1: Pipeline desync — proxy saw different number of messages
    Rule 2: One endpoint processed more complete messages
    Rule 3: Proxy and backend returned different HTTP status codes
```

**Kết quả tổng:**
```
[✓] Fuzzing Complete
    Total test cases : 48
    Discrepancies    : 40  🔴   ← Hit rate: 83%
    Skipped (timeout): 0
```

---

## SLIDE 11 — Phân Loại Kết Quả (Triage)

**Số liệu thực nghiệm (113 discrepancies tổng):**

**1. Taxonomy:**
- Request-side: Inconsistent number of messages — **25 (22.1%)** 🔴
- Request-side: Inconsistent message content — **13 (11.5%)**
- Response-side: Length discrepancy — **75 (66.4%)**

**2. Primary Discrepancies:**
- Incomplete sanitization / Validation Bypass — **50 (44.2%)**
- Raw byte difference — **48 (42.5%)**
- Non-standard number parsing — **12 (10.6%)**
- Differing TE.CL strategies — **3 (2.7%)**

**3. Attacks:**
- Response Stealing / Forgery — **48 (42.5%)**
- Request Confusing — **40 (35.4%)**
- **Request Smuggling — 25 (22.1%)** 🔴

**4. Root Causes:**
- Protocol translation (Proxy vs WSGI) — **73 (64.6%)**
- Number Parsing quirks — **26 (23%)**
- Non-standard RFC compliance — **14 (12.4%)**

> **Gợi ý người làm slide:** Vẽ lại 4 mục trên dạng 4 Donut Chart nhỏ bằng PowerPoint / Google Sheet.

---

## SLIDE 12 — Case Study: Pipeline Desync

**Payload kích hoạt lỗi (từ `crash_reports/*.json`):**

```
Mutator    : byte:inject_smuggling_prefix
Seed       : seed_08 (TE.CL Conflict)
```

**Payload thực tế được gửi qua TCP:**
```
PRI * HTTP/2.0\r\n          ← Giả mạo HTTP/2 Connection Preface
\r\n
SM\r\n
\r\n
POST / HTTP/1.1\r\n         ← Request thật ẩn sau preamble rác
Host: localhost\r\n
Content-Length: 3\r\n
Transfer-Encoding: chunked\r\n
\r\n
5\r\n
12345\r\n
0\r\n
\r\n
```

**Nginx (Proxy) nhìn thấy:**
- Gói HTTP/2.0 Preface → reject, trả `400 Bad Request`
- `message_count = 1`, `status = 400`

**Gunicorn (Backend nhận trực tiếp):**
- Bỏ qua Preface, đọc thẳng vào POST → timeout/drop
- `message_count = 0`, `status = 0`

**→ Triggered Rule 1 + Rule 2 + Rule 3: PIPELINE DESYNC**

---

## SLIDE 13 — Kết Luận

**Đóng góp của đề tài:**
1. Framework Differential Fuzzer mã nguồn mở bằng Python + Docker
2. Bộ 12 Golden Seeds có phương pháp luận Coverage-oriented
3. 14 Mutators (gồm 3 Advanced bypass C/C++ parsers)
4. Phân loại đúng chuẩn học thuật HDHunter Taxonomy
5. Ma trận 4 môi trường: Nginx, HAProxy, ATS, Apache HTTPD

**Kết quả thực nghiệm:**
- **113 discrepancies** phát hiện được
- **25 Request Smuggling** (Rule 1+2) — mức nguy hiểm cao nhất
- Hit rate: **83%** trên Golden Corpus

---

## SLIDE 14 — Hướng Phát Triển

- **Scale thêm targets:** ATS + Gevent, Apache HTTPD + Tomcat (đã dựng Docker, chưa chạy thực nghiệm)
- **HTTP/2 H2C Downgrade seeds:** Nginx downgrade từ H2 xuống H1.1 → nguồn lỗi chưa được khai thác
- **Genetic Algorithm Mutator:** Dùng payload bắt được Rule 1/2 làm mẹ, lai chéo để tạo payload mạnh hơn
- **CI/CD Integration:** Chạy fuzzer tự động mỗi khi cập nhật phiên bản Proxy mới

---

## SLIDE 15 — Demo Live (nếu có)

**Lệnh chạy trực tiếp trên máy:**
```bash
# Demo mini test suite (chạy < 5 giây)
python3 project/07_mini_test_suite/test_proxy_backend.py

# Output mong đợi:
# [Test Case] 2. Classic CL.TE Smuggling
# ─────────────────────────────────────────────────────────
#  Proxy (Nginx)  : [HTTP/1.1 400 Bad Request] (No JSON)
#  Backend (WSGI) : [HTTP/1.1 200 OK] | Parsed CL: 42 | Parsed TE: chunked
#  --> DISCREPANCY DETECTED!
```

**Kịch bản thuyết trình:**
> "Đây là cùng một gói tin, cùng một payload CL.TE Smuggling kinh điển. Nginx từ chối và trả 400 — nó thấy header xung đột. Gunicorn thì chấp nhận và đọc theo Transfer-Encoding. Đây chính là điểm mù mà kẻ tấn công khai thác."

---
*File này dùng để làm nội dung slide — số liệu lấy từ lần chạy thực nghiệm ngày 12/04/2026.*

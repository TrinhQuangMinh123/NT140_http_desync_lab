# HTTP Desync Differential Fuzzer — Nội dung báo cáo

---

## 1. Giới thiệu vấn đề


Trong kiến trúc web hiện đại, các ứng dụng thường được triển khai theo mô hình nhiều tầng: Client gửi request đến một Reverse Proxy như Nginx, HAProxy, rồi Proxy mới chuyển tiếp về Backend Server như Gunicorn, Tomcat. Cả hai thành phần này đều phải parse gói tin HTTP trước khi xử lý.

Vấn đề nảy sinh khi hai thành phần đó hiểu khác nhau về cùng một gói tin HTTP, tạo ra hiện tượng HTTP Desync. Bằng cách lợi dụng sự mất đồng bộ này ở cả hai chiều Request và Response.
---
## 1.1 Một số khái niệm cần biết

### Nội dung trên slide

| Khái niệm | Vai trò |
|---|---|
| Content-Length | Cho biết body dài bao nhiêu byte |
| Transfer-Encoding | Quy định cách truyền body, thường là chunked |
| Chunked body | Body được chia thành nhiều chunk. Mỗi chunk bắt đầu bằng một con số biểu diễn kích thước chunk, sau đó mới đến dữ liệu thật. |
| Trailer section | Metadata nằm sau body trong chunked encoding |
| CRLF | Ký tự xuống dòng chuẩn của HTTP |
| Persistent connection | Nhiều request dùng chung một TCP connection |

### Ghi chú thuyết trình
Các khái niệm này quan trọng vì HTTP Desync thường không đến từ logic ứng dụng, mà đến từ cách parser hiểu các chi tiết rất thấp như độ dài body, chunk size, trailer hoặc ký tự xuống dòng.

---
## 1.2 Vì sao HTTP Desync xảy ra?

### Nội dung trên slide

| Root cause | Giải thích ngắn |
|---|---|
| Non-standard number parsing | Server hiểu khác nhau về Content-Length hoặc chunk size |
| Trailer handling khác nhau | Một bên coi là trailer, bên kia coi là request mới |
| LF/CRLF khác nhau | Một bên chấp nhận LF, bên kia yêu cầu CRLF |
| TE.CL conflict | Một bên ưu tiên Transfer-Encoding, bên kia ưu tiên Content-Length |
| Response sanitization thiếu | Proxy không làm sạch response/CGI response trước khi forward |

### Ghi chú thuyết trình
Các lỗi này nhìn nhỏ nhưng đều ảnh hưởng đến ranh giới HTTP message. Chỉ cần hai hệ thống không thống nhất body dài bao nhiêu, dòng kết thúc ở đâu, hoặc phần nào là trailer, thì request/response queue có thể bị lệch.

---

## 1.3 Lỗ hổng 
kẻ tấn công có thể thực hiện 4 mô hình tấn công nguy hiểm:
| Attack | Ý chính | Impact |
|---|---|---|
| Request Smuggling | Giấu request phụ bên trong request chính | Bypass WAF / access control |
| Request Confusing | Làm Backend hiểu sai body hoặc độ dài dữ liệu | Bypass logic xử lý input |
| Response Stealing | Lượm response của user khác | Rò rỉ dữ liệu nhạy cảm |
| Response Forgery | Bơm response giả vào hàng đợi | Trả nội dung độc hại cho nạn nhân |

---

## 2. Thách thức và động lực nghiên cứu
Phát hiện lỗi HTTP Desync cực kỳ khó khăn vì lỗi không hiển thị rõ ràng và không gian biến thể payload là khổng lồ (hàng chục kiểu encoding, header, cấu trúc body). 

Các công cụ hiện tại như Burp Suite hay OWASP ZAP chỉ kiểm tra theo danh sách payload manually crafted. Trong khi đó, các nghiên cứu fuzzing trước đây như T-Reqs hay HDiff chủ yếu sử dụng kỹ thuật black-box fuzzing. Hạn chế của chúng là hoạt động một cách mù quáng, thiếu đi cái nhìn sâu vào trạng thái thực thi bên trong phần mềm, dẫn đến bỏ sót nhiều lỗi ở các góc ngách. Hơn nữa, chúng chỉ tập trung vào phía HTTP requests mà bỏ lỡ hoàn toàn các rủi ro desync nằm ở phía HTTP/CGI responses.

**Câu hỏi đặt ra**: Làm sao xây dựng một công cụ có thể tự động, có hệ thống kiểm tra hành vi parse HTTP, khắc phục được điểm mù của black-box fuzzing?

---


## 3. Nền tảng lý thuyết: Bài báo The Silent Danger in HTTP

Dự án này lấy cảm hứng và nền tảng trực tiếp từ bài báo khoa học "The Silent Danger in HTTP: Identifying HTTP Desync Vulnerabilities with Gray-box Testing" (USENIX Security 2025). Để giải quyết bài toán trên, nhóm tác giả đã đề xuất framework HDHUNTER với hai đột phá công nghệ chính:

* Gray-box coverage-directed differential testing: Cấy mã trực tiếp vào mã nguồn của máy chủ HTTP để thu thập State Tuple gồm 7 trạng thái cốt lõi: Count, Consumed, Body, Encoding, CL, Order và Status. Nếu hai máy chủ có bộ trạng thái này khác nhau khi nhận cùng 1 gói tin, lỗi Desync được xác nhận.
* Snapshot-based Execution: Lỗi Desync thường làm hỏng hàng đợi mạng và trạng thái TCP, gây nhiễu cho các lần test sau. Việc áp dụng cơ chế lưu và khôi phục snapshot siêu tốc giúp làm sạch trạng thái mạng, tăng tốc độ kiểm thử lên 88 lần so với khởi động lại máy chủ.

=> Nhờ phương pháp này, HDHUNTER đã phát hiện 17 lỗ hổng hoàn toàn mới và chỉ ra 5 root causes cốt lõi gây ra desync: non-standard number parsing, xử lý Trailer không đồng nhất, non-standard line separator, và sự thiếu nhất quán trong chiến lược xử lý TE.CL ở cả Request lẫn Response.

---

## 4. Phương pháp thực hiện của dự án: Differential Testing

Kế thừa lý thuyết từ HDHUNTER, dự án này áp dụng phương pháp Differential Testing thực tế trên các môi trường giả lập. Nguyên lý cốt lõi là gửi cùng một mutated payload đến hai hệ thống qua hai luồng TCP riêng biệt và so sánh output:
* Luồng 1: Gửi qua Reverse Proxy, để Proxy chuyển tiếp về Backend.
* Luồng 2: Gửi thẳng vào Backend, bỏ qua Proxy.

Cả hai endpoint đều trả về State Tuple JSON. Việc giao tiếp được thực hiện hoàn toàn bằng Raw TCP Socket, tránh việc các thư viện HTTP của Python tự chuẩn hóa header trước khi gửi, đảm bảo giữ nguyên hình thái gây lỗi của payload.

---

### 5. Kiến trúc hệ thống

Hệ thống được chia thành 7 module độc lập:
* Phase 01 — Data Preparation: Module collector.py tạo bộ Golden Seed Corpus gồm 12 seeds đại diện cho các edge-case đặc thù (Line Folding, Trailer, xung đột CL.TE). Triết lý: Coverage over Volume.
* Phase 02 — Target Environments: Bốn cặp Proxy và Backend được dựng bằng Docker Compose (Nginx/HAProxy/ATS/HTTPD sang Gunicorn/Gevent/Tomcat). Proxy tắt header normalization, Backend chạy ứng dụng trả về State Tuple.
* Phase 03 — Mutation Engine: 14 mutator chia làm 3 tầng (Sequence Level, Message Level, Byte Level). Các mutator can thiệp từ việc xáo trộn header đến chèn Null byte, mã hóa Unicode, hoặc giả mạo HTTP/2 preface.
* Phase 04 — Fuzzer Engine: runner.py điều phối vòng lặp, gửi payload qua 2 đường và thu thập State Tuple. diff_checker.py áp dụng 7 quy tắc so sánh để tìm sai lệch.
* Phase 05 — Analyzer: triage.py phân loại crash reports theo 4 tiêu chí Taxonomy, Primary Discrepancies, Attacks, và Insights.
* Phase 06 — PoC Exploit: exploit_smuggling.py chứng minh rủi ro thực tế bằng cách đính kèm request ẩn vào payload gây lỗi.
* Phase 07 — Mini Test Suite: test_proxy_backend.py là script demo độc lập với 4 payload kinh điển, in bảng so sánh trực tiếp.


---

### 6. Công cụ phân loại — 7 Rules và 4 Taxonomy

Theo chuẩn của bài báo gốc, dự án sử dụng:
* 7 quy tắc so sánh: Phân tích dựa trên 7 trường của State Tuple. Rule 1 và 2 (khác biệt message_count hoặc message_processed) báo hiệu Pipeline Desync nghiêm trọng. Các Rule 3 đến 7 bắt các sai lệch nhỏ hơn về status, header và body.
* 4 tiêu chí Taxonomy: Phân loại hình thái desync, kỹ thuật sai lệch cốt lõi, kịch bản tấn công thực tế và nguyên nhân sâu xa (ngôn ngữ lập trình, protocol conversion hay vi phạm RFC).


---

## 7. Kết quả thực nghiệm

Thực nghiệm được thực hiện trên hai môi trường đã dựng thành công: **Nginx 1.25 → Gunicorn** và **HAProxy 2.9 → Gunicorn**. Hai môi trường còn lại (ATS → Gevent, Apache HTTPD → Tomcat) chưa chạy được do phụ thuộc về Docker image và Java webapp. Mỗi môi trường chạy 12 Golden Seeds với 3 mutations/seed, tổng cộng 48 test cases.

**Tổng quan kết quả:**

| Môi trường | Test Cases | Discrepancies | Hit Rate |
|------------|-----------|---------------|----------|
| Nginx 1.25 → Gunicorn | 48 | 40 | 83.3% |
| HAProxy 2.9 → Gunicorn | 48 | 48 | **100%** |
| ATS → Gevent | — | — | N/A |
| Apache HTTPD → Tomcat | — | — | N/A |
| **Tổng** | **96** | **88** | **91.7%** |

**Môi trường 1 — Nginx:** Nginx forwarded một số gói tin bị biến dạng về Backend, dẫn đến các loại sai lệch đa dạng. Rule 4 (Transfer-Encoding stripping) và Rule 7 (response length difference) được kích hoạt nhiều — cho thấy Nginx chuẩn hóa một số header trước khi forward, tự tạo ra desync. Request Smuggling xảy ra ở 25/48 cases.

**Môi trường 2 — HAProxy:** HAProxy nghiêm ngặt hơn Nginx — nó drop hoặc reject toàn bộ 48 test cases trước khi forward về Backend. Backend vẫn xử lý bình thường khi được gửi thẳng (không qua proxy). Sự chênh lệch `message_count` giữa hai phía là 0 vs 1 cho tất cả cases — tức là Proxy không gửi bất kỳ gói nào trong khi Backend nhận được đầy đủ. Đây là dạng Pipeline Desync hoàn toàn với hit rate 100%.

**So sánh Rule activation giữa hai Proxy:**

| Rule | Nginx | HAProxy | Nhận xét |
|------|-------|---------|----------|
| Rule 1 (message_count) | 25 | 48 | HAProxy strict hơn: không forward bất kỳ payload nào |
| Rule 4 (transfer_encoding) | 13 | 0 | Nginx strip/add TE; HAProxy drop cả request |
| Rule 7 (consumed_length) | 40 | 0 | Nginx forward một phần → response diff; HAProxy không forward gì |

**Case Study tiêu biểu (Nginx):** Payload từ mutator `inject_smuggling_prefix` chèn HTTP/2 Connection Preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) vào đầu gói TE.CL conflict. Nginx đọc preamble như HTTP/2, trả `400 Bad Request` (`message_count=1`). Gunicorn nhận thẳng, bỏ qua preamble, timeout (`message_count=0`). Rule 1, 2, 3 kích hoạt — Pipeline Desync hoàn toàn.

**Case Study tiêu biểu (HAProxy):** Seed `seed_01` (Standard GET — không mutation). HAProxy drop connection, trả `message_count=0`, `status=0`. Backend nhận và xử lý bình thường: `message_count=1`, `status=200`, `body_length=0`. Rule 1, 2, 3, 5, 6, 7 đều kích hoạt — HAProxy từ chối cả request hợp lệ khi chạy trong ngữ cảnh test này, cho thấy sự không nhất quán cấu hình mặc định.

---

## 8. Kết luận và hướng phát triển


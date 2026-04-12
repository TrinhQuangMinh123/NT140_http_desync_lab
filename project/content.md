# HTTP Desync Differential Fuzzer — Nội dung báo cáo

---

## 1. Giới thiệu vấn đề

Trong kiến trúc web hiện đại, các ứng dụng thường được triển khai theo mô hình nhiều tầng: Client gửi request đến một **Reverse Proxy** (như Nginx, HAProxy), rồi Proxy mới chuyển tiếp về **Backend Server** (như Gunicorn, Tomcat). Cả hai thành phần này đều phải **phân tích cú pháp (parse) gói tin HTTP** trước khi xử lý.

Vấn đề nảy sinh khi hai thành phần đó **hiểu khác nhau về cùng một gói tin HTTP**. Hiện tượng này gọi là **HTTP Desync** (mất đồng bộ HTTP) hay còn gọi là **HTTP Request Smuggling**. Kẻ tấn công có thể lợi dụng điểm mù này để:

- Vượt qua tường lửa ứng dụng (WAF) và kiểm soát truy cập
- Chiếm session hoặc đọc response của người dùng khác
- Chèn một request trái phép ẩn vào luồng HTTP hợp lệ

Đây là lớp lỗ hổng đã được ghi nhận trong nhiều CVE nghiêm trọng như **CVE-2019-9516** (Nginx), **CVE-2022-26377** (Apache HTTPD), cũng như hàng loạt báo cáo Bug Bounty từ Portswigger Research trên các nền tảng lớn như HackerOne.

---

## 2. Thách thức và động lực nghiên cứu

Phát hiện lỗi HTTP Desync theo cách thủ công cực kỳ khó khăn vì:

- Lỗi không hiển thị rõ ràng, không có thông báo lỗi trực tiếp
- Cần phải hiểu đồng thời hành vi parse của **cả hai** hệ thống trong cùng một luồng
- Không gian biến thể payload gây lỗi rất lớn: hàng chục kiểu encoding, tiêu đề HTTP, cấu trúc body khác nhau

Các công cụ hiện tại như Burp Suite hay OWASP ZAP chỉ kiểm tra theo danh sách payload **đã biết trước** (manually crafted), không có khả năng **tự khám phá** các biến thể lỗi mới.

Câu hỏi đặt ra: Làm sao xây dựng một công cụ có thể **tự động, có hệ thống** kiểm tra hành vi parse HTTP trên nhiều cặp Proxy/Backend khác nhau?

---

## 3. Phương pháp: Differential Testing

Dự án này áp dụng phương pháp **Differential Testing** (Kiểm thử sai lệch), được đề xuất trong bài báo học thuật **HDHunter** (công bố tại hội nghị bảo mật quốc tế).

Nguyên lý cốt lõi: Gửi **cùng một input** đến hai hệ thống khác nhau qua hai luồng TCP riêng biệt, rồi so sánh output. Nếu output khác nhau mà cùng input, thì lỗi tồn tại ở đây.

Cụ thể trong dự án này:
- Input: Một gói tin HTTP đã được làm biến dạng (mutated payload)  
- Hệ thống 1: Gửi qua **Reverse Proxy** (Nginx), Proxy sẽ chuyển tiếp về Backend và trả về response
- Hệ thống 2: Gửi **thẳng vào Backend** (Gunicorn), bỏ qua Proxy

Cả hai endpoint đều được trang bị một **State Tuple** — một JSON object ghi lại cách hệ thống đó hiểu về gói tin (Content-Length bao nhiêu, Transfer-Encoding có được nhận không, body được đọc bao nhiêu byte, v.v.). Nếu hai State Tuple khác nhau → Desync.

Lý do quan trọng: Toàn bộ giao tiếp được thực hiện bằng **Raw TCP Socket**, tránh việc các thư viện HTTP của Python (như `requests`) tự sửa đổi header trước khi gửi, gây che giấu lỗi.

---

## 4. Kiến trúc hệ thống

Hệ thống được chia thành 7 module độc lập:

**Phase 01 — Data Preparation:** Module `collector.py` tạo ra bộ "Golden Seed Corpus" gồm 12 hạt giống (seeds). Mỗi seed đại diện cho một edge-case đặc thù của giao thức HTTP/1.1 — từ Line Folding, Duplicate Header, Chunked Extension, Trailer Headers cho đến các kịch bản xung đột CL.TE và TE.CL kinh điển. Triết lý thiết kế: **Coverage over Volume** — 12 seeds chất lượng cao hiệu quả hơn hàng nghìn seeds ngẫu nhiên vì mỗi seed nhắm vào một trường hợp parse cụ thể.

**Phase 02 — Target Environments:** Bốn cặp Proxy/Backend được dựng bằng Docker Compose:
- Nginx → Gunicorn (port 8888/9001)
- HAProxy → Gunicorn (port 8890/9003)
- Apache Traffic Server → Gevent (port 8889/9002)
- Apache HTTPD → Tomcat (port 8891/9004)

Tất cả proxy được cấu hình tắt header normalization để lộ hành vi parse thật. Tất cả backend chạy cùng một ứng dụng WSGI trả về State Tuple JSON giúp so sánh đồng nhất.

**Phase 03 — Mutation Engine:** 14 mutator chia làm 3 tầng. Sequence Level (2 mutators) ghép, cắt các pipeline request. Message Level (4 mutators) thao tác trực tiếp trên Header — nhân đôi, xóa, hoán đổi, thay token. Byte Level (8 mutators, gồm 3 nâng cao) can thiệp ở mức raw byte — chèn Null byte, mã hóa số bằng Unicode full-width (`１０`, `0xa`), giả mạo HTTP/2 preface để qua mặt các C parser. Mỗi lần chạy, một mutator được chọn ngẫu nhiên và áp dụng lên seed, tạo ra biến thể mới.

**Phase 04 — Fuzzer Engine:** `runner.py` điều phối toàn bộ vòng lặp fuzzing. Với mỗi seed, nó tạo ra N biến thể đột biến, gửi từng cái qua cả hai đường (Proxy + Backend Direct) và thu thập State Tuple từ hai phía. `diff_checker.py` sau đó áp dụng 7 quy tắc so sánh lấy trực tiếp từ source code Rust của HDHunter (`http_param.rs`). Khi phát hiện sai lệch, toàn bộ thông tin (payload, state tuple hai phía, rule bị kích hoạt) được lưu vào crash report.

**Phase 05 — Analyzer:** `triage.py` đọc tất cả crash reports và phân loại chúng theo 4 tiêu chí học thuật của HDHunter: Taxonomy (hình thái desync), Primary Discrepancies (sai lệch kỹ thuật), Attacks (kịch bản tấn công), Insights (nguyên nhân gốc rễ).

**Phase 06 — PoC Exploit:** `exploit_smuggling.py` nhận một payload đã phát hiện lỗi, gắn thêm một request ẩn (ví dụ: `POST /admin`), và biểu diễn cơ chế smuggling qua 2 bước TCP để chứng minh rủi ro thực tế.

**Phase 07 — Mini Test Suite:** `test_proxy_backend.py` là script độc lập, không cần chạy toàn bộ hệ thống. Nó hard-code 4 payload kinh điển (Standard, CL.TE, Line Folding, Unicode), bắn vào cả Proxy và Backend rồi in ra bảng so sánh màu để demo trực tiếp trong buổi bảo vệ.

---

## 5. Công cụ phân loại — 7 Rules và 4 Taxonomy

**7 quy tắc so sánh (từ HDHunter `http_param.rs`):**

Mỗi discrepancy được phân tích theo 7 trường của State Tuple. Rule 1 và Rule 2 là nghiêm trọng nhất — khi `message_count` hoặc `message_processed` khác nhau giữa Proxy và Backend, đó là dấu hiệu của Pipeline Desync trực tiếp. Rule 3-6 chỉ ra các sai lệch nhỏ hơn ở status code, Transfer-Encoding, Content-Length và body length. Rule 7 là kổng kích hoạt khi kích thước response thô khác nhau.

**4 tiêu chí phân loại (Taxonomy của HDHunter):**

Taxonomy mô tả hình thái desync là gì (Inconsistent number, Inconsistent content, Response-side). Primary Discrepancies chỉ ra kỹ thuật sai lệch cụ thể (CL.TE conflict, non-standard number parsing, trailer handling). Attacks ánh xạ sai lệch đó về kịch bản tấn công thực tế (Smuggling hay Confusing hay Forgery). Insights đi thẳng vào nguyên nhân gốc — lỗi nằm ở ngôn ngữ lập trình, ở protocol conversion, hay ở sự không tuân thủ RFC.

---

## 6. Kết quả thực nghiệm

Thực nghiệm được thực hiện trên môi trường Nginx → Gunicorn với 12 Golden Seeds và 3 mutations/seed (48 test cases tổng).

- **40/48 test cases kích hoạt discrepancy** — hit rate 83%
- Tổng cộng **113 discrepancies** được ghi nhận (bao gồm các lần chạy trước đó)

Phân loại theo Taxonomy:
- Request-side Inconsistent number: **25 reports (22.1%)** — Mức nghiêm trọng cao nhất (kích hoạt Rule 1+2)
- Request-side Inconsistent content: **13 reports (11.5%)**
- Response-side length discrepancy: **75 reports (66.4%)**

Phân loại theo Attacks:
- Request Smuggling: **25 reports (22.1%)**
- Request Confusing: **40 reports (35.4%)**
- Response Stealing/Forgery: **48 reports (42.5%)**

Phân loại theo Root Causes:
- Protocol translation issues (Proxy vs WSGI): **73 (64.6%)**
- Number Parsing quirks: **26 (23%)**
- Non-standard RFC compliance: **14 (12.4%)**

**Case Study tiêu biểu:** Payload được tạo bởi mutator `inject_smuggling_prefix` — nó chèn HTTP/2 Connection Preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) vào đầu gói TE.CL conflict. Nginx phân tích được preamble đó như một yêu cầu không hợp lệ và trả về `400 Bad Request` (message_count=1). Gunicorn bỏ qua preamble và timeout luôn (message_count=0). Kết quả: Rule 1, 2, 3 đồng loạt kích hoạt — Pipeline Desync hoàn toàn.

---

## 7. Kết luận và hướng phát triển

Dự án đã xây dựng thành công một framework Differential Fuzzer mã nguồn mở cho HTTP Desync, bao gồm bộ 12 Golden Seeds theo hướng Coverage-oriented, 14 mutation strategies với 3 advanced mutators cho C/C++ parsers, phân loại kết quả đúng chuẩn học thuật HDHunter, và ma trận 4 môi trường Docker mở rộng được.

Hướng phát triển tiếp theo bao gồm mở rộng thực nghiệm sang ATS và Apache Tomcat, thêm seeds cho HTTP/2 H2C Downgrade, áp dụng Genetic Algorithm để tự tiến hóa payload từ các bug đã tìm được, và tích hợp vào CI/CD pipeline để tự động kiểm tra mỗi khi cập nhật phiên bản proxy.

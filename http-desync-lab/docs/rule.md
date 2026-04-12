Dưới đây là **Bản mô tả Thiết kế Kiến trúc** chi tiết cho hệ thống Demo lỗ hổng HTTP Request Smuggling (Trailer Section Bypass), được tối ưu hóa để ghi log, xuất báo cáo và dễ dàng mở rộng cho các cặp Proxy - Backend khác trong tương lai.

---

# TÀI LIỆU THIẾT KẾ KIẾN TRÚC: HỆ THỐNG DEMO HTTP DESYNC
**Mục tiêu:** Mô phỏng, kiểm thử và đo lường sự sai lệch trong phân tích cú pháp (parsing) giữa Proxy và Backend, dẫn đến lỗ hổng HTTP Request Smuggling.
**Môi trường triển khai:** Docker & Docker Compose.

## 1. Thành phần Kiến trúc Cốt lõi (Cặp 1: ATS & gevent)

Kiến trúc được chia thành 3 node chính chạy trong một mạng nội bộ (Docker Network):

* **Node 1: Attacker / Tester Script (Python)**
    * Đóng vai trò là Client gửi các gói tin HTTP dị dạng (Payloads) được thiết kế sẵn.
    * Thu thập phản hồi (Response) và phân tích log để xuất ra file báo cáo `.json`.
* **Node 2: Front-end Proxy (Apache Traffic Server - ATS 9.2.0)**
    * Lắng nghe ở cổng 80 (hoặc 9080).
    * **Hành vi lỗi:** Nhận gói tin `Transfer-Encoding: chunked`, phát hiện có phần **Trailer Section** (siêu dữ liệu nằm sau chunk cuối) nhưng **không làm sạch (sanitize)**. Nó chuyển tiếp toàn bộ cục dữ liệu thô này xuống Backend.
* **Node 3: Application Backend (gevent 23.7.0 + Flask/WSGI)**
    * Lắng nghe ở cổng nội bộ (ví dụ: 5000).
    * **Hành vi lỗi:** Không hỗ trợ chuẩn Trailer Section. Khi nhận chuỗi Trailer từ ATS, nó **vứt bỏ dòng đầu tiên** của Trailer và xử lý phần nội dung còn lại như một **HTTP Request thứ hai hoàn toàn độc lập**.

## 2. Luồng dữ liệu và Kịch bản Khai thác (Bypass Access Control)

Kiến trúc này được thiết kế để chứng minh kịch bản kẻ tấn công vượt qua màng lọc (Access Control) của ATS để truy cập vào đường dẫn nội bộ của gevent:

1.  **Gửi Payload:** Tester Script gửi một HTTP Request sử dụng chunked encoding tới `/path1` (đường dẫn công khai, ATS cho phép).
2.  **Giấu Request 2:** Ngay trong phần Trailer Section của Request 1, Tester nhúng một Request thứ 2 nhắm tới `/path2` (đường dẫn quản trị/nội bộ, ATS cấm truy cập từ bên ngoài).
3.  **ATS Xử lý:** ATS đọc Request 1 (`/path1`), thấy hợp lệ. Nó bỏ qua việc kiểm tra Trailer và đẩy toàn bộ gói tin xuống gevent.
4.  **gevent Xử lý (Desync xảy ra):**
    * gevent nhận luồng dữ liệu, phân giải thành công Request 1 (`/path1`).
    * Tiếp theo, nó gặp phần Trailer. Do lỗi logic, gevent cắt bỏ dòng đầu tiên của Trailer, biến phần còn lại thành Request 2 (`/path2`).
    * gevent thực thi Request 2 và trả kết quả độc hại về. Hệ thống bị Smuggling thành công.

## 3. Cơ chế Ghi Log và Xuất Báo Cáo (Report)

Để hệ thống đo lường được sai khác, luồng ghi nhận dữ liệu được thiết kế như sau:

* **`raw_traffic.log` (File Log thô):**
    * Backend gevent được lập trình để in ra màn hình (stdout) toàn bộ dữ liệu raw byte nó nhận được từ ATS.
    * Script Tester sẽ lưu luồng gửi đi (Requests) và luồng trả về (Responses) từ ATS vào file log này.
* **`report.json` (Báo cáo Thống kê State Tuple):**
    * Sau mỗi lần test, Tester Script sẽ tính toán và tổng hợp trạng thái thành file JSON. Cấu trúc JSON báo cáo lỗ hổng cho cặp này sẽ có dạng:
    ```json
    {
      "test_case": "Trailer Section Injection",
      "proxy": "ATS 9.2.0",
      "backend": "gevent 23.7.0",
      "results": {
        "proxy_status": 200,
        "proxy_recognized_requests": 1,
        "backend_recognized_requests": 2,
        "smuggled_path_accessed": "/path2",
        "vulnerability_status": "CRITICAL - Smuggling Successful"
      }
    }
    ```

## 4. Cấu trúc Thư mục (Mô-đun hóa)

Để đảm bảo gọn gàng và **dễ lặp lại cho các cặp Proxy/Backend khác** (như Nginx-Gunicorn, HAProxy-NodeJS), toàn bộ source code cần được tổ chức theo cấu trúc sau:

```text
http-desync-lab/
│
├── pairs/                              <-- Chứa môi trường của các cặp máy chủ
│   ├── ats_gevent/                     <-- CẶP 1 (Demo hiện tại)
│   │   ├── docker-compose.yml          (Dựng 1 container ATS, 1 container Gevent)
│   │   ├── proxy/
│   │   │   ├── Dockerfile              (Cài đặt đúng bản ATS 9.2.0)
│   │   │   └── records.config          (Cấu hình ATS đẩy traffic về backend)
│   │   └── backend/
│   │       ├── Dockerfile              (Cài đặt đúng bản gevent 23.7.0)
│   │       └── app.py                  (App WSGI in raw log và xử lý /path1, /path2)
│   │
│   └── nginx_gunicorn/                 <-- CẶP 2 (Tạo sẵn folder cho tương lai)
│       └── ...
│
├── tester/                             <-- Bộ công cụ Test và Báo cáo (Dùng chung)
│   ├── payloads/
│   │   └── trailer_smuggle.txt         (File chứa payload raw HTTP dị dạng)
│   ├── run_test.py                     (Script Python đọc payload, bắn qua socket, đo lường)
│   └── requirements.txt
│
└── output/                             <-- Nơi xuất file kết quả tự động
    ├── ats_gevent/
    │   ├── raw_traffic.log             (Lưu log chi tiết)
    │   └── report.json                 (Báo cáo JSON thống kê)
    └── nginx_gunicorn/
```

### Lợi ích của kiến trúc này:
1.  **Cô lập:** Mỗi cặp Proxy-Backend nằm trong một thư mục `pairs/` riêng biệt với `docker-compose.yml` riêng. Bạn không sợ xung đột port hay phiên bản khi test nhiều cặp.
2.  **Tái sử dụng:** Script `run_test.py` nằm ở ngoài. Bạn chỉ cần truyền tham số (VD: `python tester/run_test.py --target ats_gevent`) là nó sẽ tự động lấy payload ném vào hệ thống tương ứng và sinh báo cáo.
3.  **Rõ ràng cho Demo:** Khi báo cáo với giáo viên, bạn chỉ cần show file `payloads/trailer_smuggle.txt` để giải thích lý thuyết, chạy lệnh, và mở file `output/.../report.json` để chứng minh kết quả "1 request biến thành 2 request".
# HTTP Desync Lab

Dự án này là một môi trường thực hành (lab) được thiết kế theo dạng module giúp bạn tìm hiểu và mô phỏng các cuộc tấn công **HTTP Request Smuggling** (hay còn gọi là HTTP Desync - Trượt đồng bộ HTTP). 

## Tổng quan

Lỗi HTTP Desync xảy ra khi hệ thống mạng có cấu hình máy chủ Proxy (như Nginx, HAProxy, ATS) nằm trước một máy chủ Backend. Nếu hai máy chủ này có cách phân tích, đọc hiểu độ dài gói tin HTTP khác nhau, kẻ tấn công có thể "giấu" (smuggle) thêm một yêu cầu lén lút bên trong yêu cầu ban đầu. 

Framework này hỗ trợ mô phỏng trên **nhiều bộ đôi Proxy/Backend khác nhau**. Mỗi cặp sẽ chạy trong một môi trường Docker độc lập, kết hợp với một công cụ tấn công dùng chung để dễ dàng tái sử dụng cho nhiều kịch bản.

## Cấu trúc thư mục

```
http-desync-lab/
├── pairs/                          # Cấu hình các bộ đôi Proxy/Backend
│   ├── ats_gevent/                 # Demo lỗ hổng trên ATS 9.2.0 + gevent 23.7.0
│   │   ├── docker-compose.yml      # Script chạy container tự động
│   │   ├── proxy/                  # Cấu hình và Dockerfile cho ATS proxy
│   │   └── backend/                # Mã nguồn ứng dụng backend (gevent)
│   ├── nginx_gunicorn/             # (Dự kiến) Demo Nginx + Gunicorn
│   └── haproxy_nodejs/             # (Dự kiến) Demo HAProxy + Node.js
├── attacker/                       # Công cụ kiểm thử lõi dùng chung
│   ├── main.py                     # Quản lý và điều phối các bài test
│   ├── sender.py                   # Gửi gói tin HTTP thô qua TCP socket
│   ├── utils.py                    # Tiện ích ghi log và tạo báo cáo
│   ├── testcases/                  # Các kịch bản tấn công (testcases)
│   │   └── tc_01_trailer_injection.py
│   └── tests/                      # Chứa các bài unit test của công cụ
├── tester/                         # Nơi người dùng thực thi công cụ
│   ├── run_test.py                 # File thực thi chính của người dùng
│   └── payloads/                   # Các gói tin payload thô dựng sẵn
│       └── trailer_smuggle.txt
├── output/                         # Mục chứa kết quả (Tự sinh ra khi chạy)
│   └── ats_gevent/
│       ├── raw_traffic.log         # Nhật ký gói tin chi tiết
│       └── report.json             # Báo cáo dạng JSON dễ đọc
└── docs/                           # Tài liệu bổ sung
```

## Bắt đầu nhanh

### Yêu cầu cài đặt
- Docker và Docker Compose
- Python 3.7 trở lên

### Các bước chạy một bài test

1. **Khởi động cặp Proxy/Backend mục tiêu:**
   ```bash
   cd http-desync-lab/pairs/ats_gevent
   docker compose up -d
   cd ../..
   ```

2. **Khởi chạy công cụ tấn công:**
   ```bash
   python tester/run_test.py --target ats_gevent
   ```

3. **Xem và phân tích kết quả:**
   ```bash
   cat output/ats_gevent/raw_traffic.log
   cat output/ats_gevent/report.json
   ```

4. **Tắt hệ thống sau khi test xong:**
   ```bash
   cd http-desync-lab/pairs/ats_gevent
   docker compose down
   cd ../..
   ```

## Hướng dẫn sử dụng chi tiết

### Các tham số dòng lệnh

```bash
python tester/run_test.py --target <tên_cặp_server> [--host <host>] [--port <port>]
```

**Chi tiết:**
- `--target`: (Bắt buộc) Tên của cặp Proxy/Backend muốn test (ví dụ: `ats_gevent`)
- `--host`: (Tùy chọn) Địa chỉ IP/Domain của Proxy (mặc định: `localhost`)
- `--port`: (Tùy chọn) Cổng của Proxy (mặc định: `9080`)

**Một số ví dụ:**
```bash
# Chạy với cặp ats_gevent trên cổng mặc định (9080)
python tester/run_test.py --target ats_gevent

# Chạy với địa chỉ và cổng tùy chỉnh
python tester/run_test.py --target ats_gevent --host 192.168.1.100 --port 8080

# Chạy trực tiếp từ module `attacker`
python -m attacker.main --target ats_gevent
```

## Đọc hiểu kết quả đầu ra

### File `raw_traffic.log`
Chứa toàn bộ nhật ký giao tiếp mạng, giúp bạn theo dõi chi tiết những gì đã xảy ra:
- Dung lượng byte đã gửi đi.
- Dung lượng byte nhận về từ Proxy.
- Standard Output (stdout) của Backend: Giúp bạn biết chính xác *Backend đã thực sự nhận và xử lý yêu cầu nào* ẩn bên dưới.

### File `report.json`
Báo cáo phân tích tự động dưới định dạng cấu trúc:

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

**Các thông số cần lưu ý:**
- Nếu `backend_recognized_requests` (số request backend thấy) **lớn hơn** `proxy_recognized_requests` (số request proxy thấy), tức là cuộc tấn công ĐÃ THÀNH CÔNG (lọt được một request lén lút!).
- `smuggled_path_accessed`: Đoạn URL mà request "lậu" đã truy cập thành công đến backend.
- `vulnerability_status`: Đánh giá mức độ lỗ hổng.

## Cách thêm một cặp Proxy/Backend mới

Giả sử bạn muốn tự dựng một môi trường `nginx_gunicorn` để test. Bạn chỉ cần thực hiện các bước:

### Bước 1: Tạo cấu trúc thư mục
```bash
mkdir -p http-desync-lab/pairs/nginx_gunicorn/{proxy,backend}
```

### Bước 2: Tạo file docker-compose.yml
Viết file `http-desync-lab/pairs/nginx_gunicorn/docker-compose.yml`:

```yaml
version: '3.8'
services:
  proxy:
    build:
      context: ./proxy
    ports:
      - "9080:80"
    networks:
      - pair_network
  backend:
    build:
      context: ./backend
    networks:
      - pair_network
networks:
  pair_network:
    driver: bridge
```

**Yêu cầu bắt buộc:**
- Tên 2 dịch vụ (service) phải là `proxy` và `backend`.
- Proxy phải publish ra cổng `9080`.
- Sử dụng chung mạng lưới có tên `pair_network`.
- Backend phải ghi log các yêu cầu tải web ra màn hình console (stdout) để công cụ đọc được.

### Bước 3 & Bước 4: Thêm mã nguồn Proxy và Backend
Tiếp tục thêm `Dockerfile` và file cấu hình cho Nginx vào thư mục `./proxy`.
Thêm mã nguồn web (Python) và `Dockerfile` vào thư mục `./backend`.

### Bước 5: Chạy test
Hệ thống sẽ tự động nắm bắt và sử dụng cặp môi trường mới vừa tạo mà không cần chỉnh sửa mã nguồn python ở phần `attacker/`.

```bash
cd http-desync-lab/pairs/nginx_gunicorn
docker compose up -d
cd ../..
python tester/run_test.py --target nginx_gunicorn
```

## Kịch bản tấn công hiện có (Test Caces)

### Bài: Tiêm mã vào HTTP Trailer (`tc_01_trailer_injection.py`)

Khai thác sự khác biệt trong việc lý giải phần `Trailer` ở cuối gói tin HTTP chunked. Cuộc tấn công giấu toàn bộ một Request thứ hai ẩn sâu bên trong vùng dữ liệu Trailer. Khi Proxy bỏ qua Trailer nhưng Backend vẫn xử lý (hoặc ngược lại), request bị giấu sẽ lộ diện và thực thi lén lút.

**Mục tiêu áp dụng:**
- Bộ đôi `ats_gevent` (Apache Traffic Server 9.2.0 + gevent 23.7.0).

**File payload mẫu:** `tester/payloads/trailer_smuggle.txt`

## Kiến trúc phần mềm

### Nguyên tắc thiết kế (Separation of Concerns)

1. **Cô lập hạ tầng**: Từng bộ thử nghiệm (`pairs/`) hoàn toàn biệt lập với nhau bằng Docker.
2. **Logic độc lập**: Phần mã khai thác (`attacker/`) có thể tái sử dụng cho bất kỳ server nào mà không cần viết lại mã logic tấn công.
3. **Phân tách Dữ liệu và Mã**: Payload file tĩnh nằm ở `payloads/` được tách riêng khỏi logic thực thi.

## Dành cho phát triển thử nghiệm

### Cách chạy Unit Tests

```bash
# Test riêng các hàm logic tấn công
pytest http-desync-lab/attacker/tests/

# Test Integration toàn hệ thống
pytest http-desync-lab/test_e2e_integration.py

# Test toàn bộ thư mục
pytest http-desync-lab/
```

## ⚠️ Cảnh báo Bảo mật
Công cụ/Framework này sinh ra **CHỈ dành cho mục đích giáo dục, nghiên cứu và kiểm thử hệ thống được cho phép**.
Lỗi HTTP Request Smuggling là một rủi ro cực kì nghiêm trọng dẫn tới:
- Vượt qua các tường lửa/bộ lọc (WAF bypass)
- Xâm nhập tài khoản người dùng khác (Request hijacking)
- Giải độc vùng nhớ đệm chữ kí (Cache poisoning)
- Leo thang đặc quyền

**Chỉ dùng công cụ trên các hệ thống thuộc sở hữu của bạn hoặc đã có sự cho phép bằng văn bản!**


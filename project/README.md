# 🕷️ HDHunter (Python Edition) - HTTP Desync Differential Fuzzer


Mục tiêu cốt lõi của hệ thống là tự động dò quét và phát hiện các lỗ hổng **HTTP Request Smuggling (HTTP Desync)** bằng phương pháp **Differential Testing** (Kiểm thử sai lệch) giữa các Reverse Proxy và Backend.

---

## 🏗️ Kiến Trúc Hệ Thống (The 6-Phase Pipeline)

Hệ thống được chia làm 6 module độc lập (loosely-coupled), giúp dễ dàng scale và tinh chỉnh từng phần:

### 1. Phân Tích & Chuẩn Bị Dữ Liệu (`01_data_prep`)
- `collector.py`: Sinh ra các mẫu Payload HTTP có chủ đích (gắn các cặp Header mâu thuẫn như TE-CL) hoặc bắt gói tin từ PCAP thực tế.
- `parser.py`: Bóc tách gói tin HTTP thô thành 3 vùng: `Start-line`, `Field-lines`, `Body` để Mutator dễ dàng nhắm mục tiêu chuẩn xác.

### 2. Môi Trường Mục Tiêu (`02_targets`)
Quên đi Vagrant và QEMU nặng nề, chúng ta sử dụng Docker Compose.
- Chạy hệ thống Nginx (Proxy - `port 8888`) đứng trước Gunicorn WSGI (Backend - `port 9001`).
- **Điểm yếu cốt lõi:** Gunicorn backend chạy ứng dụng `app.py` được chỉnh sửa đặc biệt. Nó không trả về HTML, mà trả về một khối JSON chứa thông số kỹ thuật nội bộ mà Backend hiểu về request (gọi là **State Tuple** - quy định kích thước body, số lượng request, TE/CL headers).

### 3. Động Cơ Đột Biến (`03_mutator`)
Tái hiện toàn bộ ma thuật Fuzzing của HDHunter từ Rust sang Python:
- `sequence_level.py`: Cắt ghép, gộp các pipeline request (Splice, Remove).
- `message_level.py`: Tráo đổi Header Token, trùng lặp Header, sửa đổi kết cấu cấu trúc.
- `byte_level.py`: Đột biến ở mức Raw Byte (Thêm xóa byte, thay đổi độ dài tự nhiên).
- 🌟 **`advanced_level.py`**: **Điểm ăn tiền mở rộng.** Các mutator siêu dị dạng liên quan tới Line-folding, Full-width Unicode (１０ thay vì 10), Null bytes. Các mutator này chuyên nhằm bóp nát các Parser C/C++ chuẩn xác nhất.

### 4. Fuzzer Engine (`04_fuzzer_engine`)
Bộ não của quá trình Fuzzing nằm ở `runner.py`:
1. Mở kết nối TCP thuần (Raw Socket) để tránh can thiệp của thư viện HTTP Python chuẩn.
2. Bắn payload đột biến vào **Proxy** và **Backend** CÙNG MỘT LÚC.
3. Chạy `diff_checker.py`: Áp dụng 7 Rules so sánh (dựa hoàn toàn vào source `http_param.rs` của HDHunter).
4. Nếu cả 2 hệ thống nhìn nhận gói tin khác nhau (Vd: Nginx thấy size=10, Gunicorn thấy size=0) -> Ghi nhận Crash vào thư mục Analyzer.

### 5. Bộ Triage Cấp Độ Học Thuật (`05_analyzer`)
Chạy `triage.py` để phân tích hàng trăm Discrepancy Log (Crash reports). Nó tự động nhóm các lỗi này theo chuẩn 4 mức độ của bài báo nghiên cứu HDHunter:
- **Taxonomy:** Pipeline Desync hay Length Desync?
- **Discrepancies:** Lỗi do Validation hay do Non-standard Parsing?
- **Attacks:** Nó sẽ sinh ra Request Smuggling hay Confusing?
- **Insights:** Chỉ ra thủ phạm gốc rễ nàm ở đâu.

### 6. Chứng Minh Rủi Ro (`06_exploits_poc`)
`exploit_smuggling.py`: Script mang tính vũ khí hóa (Weaponization). Nó lấy một payload gây ra Pipeline Desync, nhét vào đuôi một lệnh Admin trái phép và biểu diễn cách vượt hàng rào Proxy Nginx một cách gọn gàng bằng TCP Socket 2 chặng.

---

## 🚀 Hướng Dẫn Chạy (Quickstart)

Thiết lập môi trường làm việc trên Linux. Cần Python 3.10+ và Docker.

**Bước 1: Khởi động hệ thống nạn nhân (Targets)**
```bash
cd project/02_targets/nginx_gunicorn
docker compose up -d --build
```
*(Bạn có thể check health bằng lệnh: `python3 ../monitor.py --action health`)*

**Bước 2: Tạo bộ Hạt giống (Seeds)**
```bash
cd project/01_data_prep
python3 collector.py    # Gen traffic PCAP
python3 parser.py       # Tách ra folder seeds_db
```

**Bước 3: Chạy Fuzzer Dò Lỗi**
```bash
cd project/04_fuzzer_engine
# Fuzz nhanh: 5 bản đột biến trên mỗi seed. 
python3 runner.py --mutations 5 --quiet
```
*(Các file báo cáo lỗi sẽ được ném vào `05_analyzer/crash_reports/`)*

**Bước 4: Phân Loại Và Viết Báo Cáo**
```bash
cd project/05_analyzer
python3 triage.py
```

---

## 🔍 Những File Code Phải Đọc! 
(Dặn bạn làm chung tập trung vào các file này nếu cần thuyết trình bảo vệ kiến trúc)

1. `04_fuzzer_engine/diff_checker.py`: Chứa **7 Rules** thần thánh quyết định thế nào là một "sai lệch". Giải thích được file này là giải thích được toàn bộ phương pháp luận Differential Testing.
2. `02_targets/nginx_gunicorn/backend/app.py`: Giải thích tại sao chúng ta hack vào WSGI app để lấy `State Tuple` JSON về, thay vì dùng Shared Memory như nền tảng QEMU.
3. `05_analyzer/triage.py`: Bộ não Triage mang giá trị học thuật nhất dự án.
4. `03_mutator/advanced_level.py`: Để khoe với thầy rắng báo cáo không chỉ clone lại làm bằng Python, mà còn research thêm các đột biến Unicode hiếm gặp.

> Tác giả/Main Dev: Lê Hữu Hoàng

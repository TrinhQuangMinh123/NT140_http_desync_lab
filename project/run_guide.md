# Hướng dẫn chạy thực nghiệm và ghi kết quả

Tài liệu này hướng dẫn từng bước chạy fuzzer trên từng môi trường mục tiêu và ghi kết quả vào `result.md` một cách khoa học.

---

## Yêu cầu trước khi chạy

- Docker và Docker Compose đã được cài đặt và đang chạy
- Python 3.10+
- Tất cả lệnh chạy từ thư mục gốc: `HDHunter/project/`

---

## Bước 0: Sinh Golden Seeds

Luôn chạy bước này đầu tiên để đảm bảo bộ seed mới nhất:

```bash
python3 01_data_prep/collector.py
```

Kết quả: 12 file `.txt` được tạo trong `01_data_prep/seeds_db/`.

---

## Bước 1: Chạy từng môi trường

### Môi trường 1 — Nginx + Gunicorn (Port 8888 / 9001)

```bash
# Dựng môi trường
cd 02_targets/nginx_gunicorn
docker compose up -d --build
cd ../..

# Chờ 5 giây cho backend khởi động
sleep 5

# Kiểm tra proxy đang nhận kết nối
curl -s --max-time 3 http://127.0.0.1:8888/ | head -2

# Chạy fuzzer (lưu output ra file tạm)
python3 04_fuzzer_engine/runner.py \
  --proxy-port 8888 \
  --backend-port 9001 \
  --label nginx_gunicorn \
  --mutations 3 \
  --quiet \
  > /tmp/fuzz_nginx.txt 2>&1

echo "Done: Nginx+Gunicorn"
```

---

### Môi trường 2 — HAProxy + Gunicorn (Port 8890 / 9003)

```bash
cd 02_targets/haproxy_flask
docker compose up -d --build
cd ../..

sleep 5
curl -s --max-time 3 http://127.0.0.1:8890/ | head -2

python3 04_fuzzer_engine/runner.py \
  --proxy-port 8890 \
  --backend-port 9003 \
  --label haproxy_flask \
  --mutations 3 \
  --quiet \
  > /tmp/fuzz_haproxy.txt 2>&1

echo "Done: HAProxy+Gunicorn"
```

---

### Môi trường 3 — Apache Traffic Server + Gevent (Port 8889 / 9002)

> **Lưu ý:** ATS không có Docker image chính thức trên Docker Hub. Cần build thủ công hoặc dùng image thay thế.
> Nếu không có ATS, bỏ qua và ghi vào `result.md`: *"Environment not available: ATS image requires manual build"*

```bash
# Kiểm tra image có sẵn không
docker image inspect trafficserver:9.2 2>/dev/null || echo "ATS image not found"

# Nếu có image:
cd 02_targets/ats_gevent
docker compose up -d --build
cd ../..

sleep 8
curl -s --max-time 3 http://127.0.0.1:8889/ | head -2

python3 04_fuzzer_engine/runner.py \
  --proxy-port 8889 \
  --backend-port 9002 \
  --label ats_gevent \
  --mutations 3 \
  --quiet \
  > /tmp/fuzz_ats.txt 2>&1

echo "Done: ATS+Gevent"
```

---

### Môi trường 4 — Apache HTTPD + Tomcat (Port 8891 / 9004)

> **Lưu ý:** Tomcat cần một webapp Java deploy sẵn. Backend mặc định trong `apache_tomcat/backend/` là Python WSGI — không tương thích với Tomcat trực tiếp.
> Nếu chưa có webapp, bỏ qua và ghi vào `result.md`: *"Environment not available: Tomcat requires Java webapp deployment"*

```bash
# Kiểm tra image
docker image inspect tomcat:10.1-jdk17 2>/dev/null || echo "Tomcat image not found"

cd 02_targets/apache_tomcat
docker compose up -d --build
cd ../..

sleep 10
curl -s --max-time 3 http://127.0.0.1:8891/ | head -2

python3 04_fuzzer_engine/runner.py \
  --proxy-port 8891 \
  --backend-port 9004 \
  --label apache_tomcat \
  --mutations 3 \
  --quiet \
  > /tmp/fuzz_apache.txt 2>&1

echo "Done: Apache+Tomcat"
```

---

## Bước 2: Chạy Triage tổng hợp

Sau khi chạy tất cả (hoặc các môi trường khả dụng):

```bash
python3 05_analyzer/triage.py > /tmp/triage_all.txt 2>&1
cat /tmp/triage_all.txt
```

---

## Bước 3: Ghi kết quả vào result.md

### Cấu trúc result.md khoa học

`result.md` nên có cấu trúc sau — **không paste raw terminal output**, chỉ ghi số liệu tổng hợp và quan sát:

```
# Experimental Results

## Setup
- Date:
- Seeds: 12 Golden Seeds
- Mutations per seed: 3
- Total test cases per environment: 48

## Results per Environment

### Environment 1: Nginx + Gunicorn
- Total test cases: 48
- Discrepancies found: X
- Hit rate: X%
- Rules triggered: (liệt kê các Rule nổi bật)
- Triage summary: (copy từ triage output)

### Environment 2: HAProxy + Gunicorn
...

## Comparative Analysis
- Bảng so sánh giữa các môi trường
- Nhận xét sự khác biệt
```

### Cách đọc kết quả từ file tạm

```bash
# Xem tổng kết từng môi trường
grep -A3 "Fuzzing Complete" /tmp/fuzz_nginx.txt
grep -A3 "Fuzzing Complete" /tmp/fuzz_haproxy.txt

# Đếm từng loại Rule bị kích hoạt
grep "Rule 1" /tmp/fuzz_nginx.txt | wc -l
grep "Rule 1" /tmp/fuzz_haproxy.txt | wc -l

# Xem triage tổng
cat /tmp/triage_all.txt
```

---

## Bước 4: Dừng các môi trường sau khi xong

```bash
cd 02_targets/nginx_gunicorn && docker compose down && cd ../..
cd 02_targets/haproxy_flask && docker compose down && cd ../..
# Nếu có ATS/Tomcat:
# cd 02_targets/ats_gevent && docker compose down && cd ../..
# cd 02_targets/apache_tomcat && docker compose down && cd ../..
```

---

## Lưu ý về ATS và Apache/Tomcat

| Môi trường | Trạng thái | Lý do |
|---|---|---|
| Nginx + Gunicorn | ✅ Đã chạy | Image python:slim có sẵn |
| HAProxy + Gunicorn | ✅ Đã chạy | Image haproxy:2.9 có sẵn |
| ATS + Gevent | ⚠️ Cần build | `trafficserver:9.2` không có trên Docker Hub public |
| Apache + Tomcat | ⚠️ Cần setup | Tomcat cần deploy Java webapp riêng |

Với ATS: có thể dùng `ubuntu:22.04` base image và cài ATS bằng `apt` thay thế. Mình có thể viết Dockerfile nếu bạn muốn thử.

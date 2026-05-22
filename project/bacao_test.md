# Bao cao thu nghiem run lai de quy trinh request smuggling

## Thong bao tra ve
- Da thu cac target dinh nghia san trong repo theo thu tu uu tien khong dung fuzzer neu khong bat buoc.
- Da build va chay thanh cong cac stack: `nginx_gunicorn`, `haproxy_flask`, `ats_gevent`.
- Da chay PoC co san `06_exploits_poc/exploit_smuggling.py` tren cac payload lay tu `05_analyzer/crash_reports`, nhung chua xac nhan duoc smuggle exploit that su theo kieu queue/ruot response nhu mo ta trong bao cao.
- Da chay `07_mini_test_suite/test_proxy_backend.py` tren Nginx va thu duoc discrepancy ro rang o cac case CL.TE, TE.CL va obfuscated TE.

## Thu tu da thu

### 1. Nginx -> Gunicorn
Da build target thanh cong va chay PoC voi payload lay tu report Nginx:
- `05_analyzer/crash_reports/discrepancy_nginx_gunicorn_20260415_013006_686134.payload`

Ket qua:
- Response dau tien timeout hoac khong tao duoc queue response hop le.
- Khong xac nhan duoc smuggled response trong lan goi decoy tiep theo.

### 2. HAProxy -> Flask/Gunicorn
Da build target thanh cong va thu cac payload report cua HAProxy:
- `05_analyzer/crash_reports/discrepancy_haproxy_flask_20260415_013116_950354.payload`
- `05_analyzer/crash_reports/discrepancy_haproxy_flask_20260415_013049_452325.payload`
- `05_analyzer/crash_reports/discrepancy_haproxy_flask_20260415_013106_910484.payload`
- `05_analyzer/crash_reports/discrepancy_haproxy_flask_20260415_013059_474953.payload`
- `05_analyzer/crash_reports/discrepancy_haproxy_flask_20260415_013111_918204.payload`
- `05_analyzer/crash_reports/discrepancy_haproxy_flask_20260415_013121_972375.payload`

Ket qua:
- Co response 200 OK o mot so payload.
- Khong xac nhan duoc response smuggled dung nghia; output chi cho thay parser mismatch hoac response binh thuong.
- Payload TE.CL con tra ve them `400 Bad request` tu proxy/backend, khong phu hop de ket luan exploit thanh cong.

### 3. ATS -> Gevent
Da build target thanh cong va thu cac payload report cua ATS:
- `05_analyzer/crash_reports/discrepancy_ats_gevent_20260415_013609_787445.payload`
- `05_analyzer/crash_reports/discrepancy_ats_gevent_20260415_013409_825954.payload`

Ket qua:
- Payload pipelining tra ve 2 response JSON ro rang, nhung chi la discrepancy, khong phai smuggle exploit xac nhan.
- Payload CL.TE tra ve response binh thuong o request dau va response GET / o request sau, khong co dau hieu queue response /admin_bypass.

### 4. Apache HTTPD -> Tomcat
Khong tien hanh PoC exploit chuyen sau nhu ba target tren trong phien nay.
- Da doc cau hinh compose va report de doi chieu.
- Mini test / payload exploit khong duoc uu tien vi yeu cau la dung script co san va thu target thanh cong dau tien.

## Script va cong cu da dung
- `run_all.sh` de doc matrix target va hieu luong chay san.
- `06_exploits_poc/exploit_smuggling.py` de thu weaponized payload voi smuggled request chen them.
- `07_mini_test_suite/test_proxy_backend.py` de xac nhan discrepancy khong can fuzzer.
- `01_data_prep/collector.py` va `05_analyzer/triage.py` de doi chieu seed/report va loc ca co `rule 1/2`.

## Ket luan
- Neu dinh nghia thanh cong la build va exploit nhu trong bao cao de de cap toi, thi trong phien nay chua co target nao cho ket qua exploit xac nhan hoan toan.
- Neu dinh nghia thanh cong la build xong va cho thay discrepancy ro rang theo bao cao, thi Nginx -> Gunicorn da thanh cong qua mini test suite dau tien.
- Huong tiep theo hop ly neu muon tien den exploit that su: chinh lai payload/PoC cho khop parser hoac quay sang fuzzing de lay payload exploitable chinh xac hon.
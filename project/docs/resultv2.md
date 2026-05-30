# BÁO CÁO THỰC NGHIỆM — v2 (sau refactor faithful)

> **Quan hệ với v1:** `resultv1.md` là baseline **trước refactor** — 935 report, 4 env, đo
> *black-box* (quan sát response) + coverage.py *xấp xỉ*, **không có** parser-internal state.
> Bản v2 này là kết quả **sau khi nâng pipeline lên "faithful" đúng-paper trên request-side**:
> backend gunicorn chạy **dưới Witcher-python** (coverage bitmap interpreter-level qua SysV shm
> `__AFL_SHM`) + parser vá ghi **HttpParam 7-tuple thật**, runner đọc out-of-band mỗi request.
>
> **Mọi con số trong file này được verify trực tiếp từ `05_analyzer/trace_full_*.jsonl`** (15 file,
> 719 dòng), không chỉ trích lại — script kiểm: gom theo env, đếm discrepancy/coverage/B6/B8.
>
> Nguồn chi tiết kèm diễn giải: `05_analyzer/RESULT_witcher_full.md`. Bản này là **tổng hợp gọn
> để nộp**, có mục **thừa nhận phần còn thiếu** (§9).

---

## 0. Phạm vi số liệu

- Nguồn: `05_analyzer/trace_full_<env>_<seed>.jsonl` — **3 env faithful × 5 RNG seed = 15 file**.
- **719 logical case request-side** (3 env × 5 seed × 12 golden seed × ~4 variant; 1 case ATS lỗi
  compose-timeout bị bỏ → 719/720).
- Mỗi case: backend gunicorn **dưới Witcher-python** (bitmap 65536) + **parser vá** ghi HttpParam shm;
  runner đọc out-of-band: `reset → proxy → đọc → reset → direct → đọc`.
- Tái lập: `bash 05_analyzer/run_witcher_full.sh` → `python3 05_analyzer/analyze_witcher_full.py 05_analyzer`.

---

## 1. Cấu hình chạy

| Hạng mục | Giá trị |
|---|---|
| RNG seeds | 1337, 1338, 1339, 1340, 1341 |
| Env (faithful) | NGINX→Gunicorn, HAProxy→Gunicorn, **ATS→Gunicorn** (đều backend gunicorn-under-Witcher) |
| Request seeds | 12 golden HTTP request seeds |
| Mutations/seed | 3 + 1 original = 48 logical case / (env, seed) |
| Coverage | Witcher bitmap, reset/đọc out-of-band qua SysV shm mỗi request (R3) |
| Internal-state | HttpParam 7-tuple shm thật (Count / Consumed / CL / chunked) |
| Snapshot/reset | shm zero trước mỗi request (thay `RESTART_EVERY=1` của v1) |
| gunicorn | 1 worker / 1 thread / `--preload` (tất định, R4) |

> **Lưu ý đổi backend ATS:** v1 chạy ATS→**gevent**. gevent dựng trên C-extension không biên dịch được
> dưới interpreter Witcher (cùng lớp rào cản với Tomcat/Java — xem §9), nên v2 trỏ ATS vào **chính
> backend gunicorn-under-Witcher** → env thành **ATS→Gunicorn**. Lợi: cô lập đúng **biến PROXY**
> (ATS vs nginx vs haproxy) trên cùng một backend đo đầy đủ. Hại: không còn khớp backend gevent của v1
> ⇒ ô ATS chỉ so **tương đối** với v1.

---

## 2. Tổng quan & so sánh trực tiếp với v1

| Chỉ số | v1 (trước refactor) | v2 (faithful) |
|---|---:|---:|
| Env faithful (coverage + state THẬT) | 0/4 | **3/4** (nginx, haproxy, ats→gunicorn) |
| Logical case request-side | 960 (4 env) | **719** (3 env faithful) |
| Discrepancy request-side | 559 (58.2%) | **403 (56.1%)** |
| Coverage fingerprint có mặt | ~0% (mostly null) | **718/719 (99.9%)** |
| Parser-internal state THẬT | ❌ (đoán từ `raw_response_length`) | ✅ Count/Consumed/CL/chunked |
| Lọc nhiễu tầng-quan-sát (B6) | ❌ | ✅ (§6) |
| Đo điểm mù coverage (B8) | ❌ | ✅ (§7) |

**Hit-rate 56.1% sát mức 58.2% của v1** ⇒ pipeline faithful **tái lập đúng profile cũ**, đồng thời
gắn được bằng chứng nội bộ cho từng discrepancy. Đây là điểm bán-được: cùng hành vi, nhưng giờ
*chứng minh được* discrepancy nào là desync framing thật vs nhiễu wire.

> **Không claim khớp số tuyệt đối với HDHunter paper.** Target/engine/quy mô khác paper (xem §10).
> Cái v2 tái lập là **CƠ CHẾ** (gray-box edge bitmap interpreter-level = đúng cơ chế Witcher của paper
> + 7-tuple internal-state) và **HÀNH VI ĐỊNH TÍNH**, không phải Bảng 2 của paper.

---

## 3. Request-side discrepancies theo env × seed

| Môi trường | s1337 | s1338 | s1339 | s1340 | s1341 | Tổng | Hit rate | v1 (cũ) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| NGINX 1.25 → Gunicorn | 32 | 38 | 34 | 32 | 31 | **167** | 69.6% | 165 (68.8%) |
| HAProxy 2.9 → Gunicorn | 21 | 25 | 26 | 18 | 28 | **118** | 49.2% | 121 (50.4%) |
| ATS → Gunicorn ¹ | 23 | 25 | 21 | 23 | 26 | **118** | 49.4% | 126 (52.5%)¹ |
| **Tổng** | 76 | 88 | 81 | 73 | 85 | **403** | **56.1%** | 559 (58.2%, 4 env) |

¹ Ô v1 là ATS→**gevent**; v2 là ATS→**gunicorn** ⇒ chỉ so tương đối (cùng proxy ATS, khác backend).

NGINX gần trùng khít (167 vs 165), HAProxy sát (118 vs 121) ⇒ con số faithful ổn định, không phải nhiễu.

---

## 4. Rule frequency theo env (5 seed)

| Môi trường | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | R9 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| NGINX → Gunicorn | 64 | 64 | 110 | 93 | 49 | 73 | 160 | 124 | 22 |
| HAProxy → Gunicorn | 45 | 45 | 30 | 27 | 44 | 21 | 106 | 57 | 38 |
| ATS → Gunicorn | 29 | 29 | 30 | 18 | 42 | 13 | 73 | 44 | 28 |

R7 (`raw_response_length`) vẫn nhiều nhất ở mọi env — đúng cảnh báo "tín hiệu rộng, cần replay" của v1,
nay được B6 (§6) lọc lại bằng state thật. R8 (order-oracle) mạnh trên NGINX (124) khớp nhận xét v1.

---

## 5. Mutation distribution (total / → discrepancy)

| Mutation | Total | → Disc |
|---|---:|---:|
| original | 180 | 99 |
| sequence:splice | 89 | 70 |
| sequence:remove | 62 | 35 |
| byte:perturb_content_length | 45 | 16 |
| message:node_typed_swap | 43 | 24 |
| message:trailer_section_replace | 35 | 17 |
| message:field_line_duplicate | 34 | 20 |
| message:node_token_replace | 28 | 16 |
| byte:byte_remove | 27 | 17 |
| byte:byte_duplicate | 23 | 9 |

`original` + `sequence:*` đóng góp nhiều nhất — golden seed vốn là các edge-case HTTP/1.1 mơ hồ
(duplicate CL, TE.CL, CL.TE, trailer, pipelining).

---

## 6. [MỚI] B6 — internal-state corroboration (lọc nhiễu tầng-quan-sát)

Dùng HttpParam THẬT 2 phía hỏi: discrepancy có được parse-state nội bộ xác nhận (proxy-parse ≠ direct-parse)?

| Môi trường | Disc | Có divergence state THẬT | Response-observation-only |
|---|---:|---:|---:|
| NGINX → Gunicorn | 167 | **106 (63%)** | 61 (37%) |
| HAProxy → Gunicorn | 118 | **40 (34%)** | 78 (66%) |
| ATS → Gunicorn | 118 | **31 (26%)** | 87 (74%) |

→ Lần đầu **định lượng được** tỷ lệ "nhiễu tầng-quan-sát" theo proxy: **NGINX desync framing thật nhiều
nhất (63%)**, còn HAProxy/ATS phần lớn discrepancy chỉ ở tầng wire/forwarding (cần replay). v1 (không có
state) không thể đưa ra kết luận này.

---

## 7. [MỚI] B8 — điểm mù coverage (deliverable học thuật chính)

Gom case theo `cov_fingerprint` (direct), tìm nhóm **cùng tập edge** nhưng **state THẬT khác**:

| Môi trường | Nhóm fingerprint mù |
|---|---:|
| NGINX → Gunicorn | 5 |
| HAProxy → Gunicorn | 5 |
| ATS → Gunicorn | 5 |

Ví dụ (lặp lại nhất quán trên cả 3 env):
- `fp 3d0577…` (cùng edge, `chunked=True`) ⇒ `consumed_real=[5]` **vs** `[11]`.
- `fp 49911f…` ⇒ `consumed=[5]` **vs** `[11]` (chunked).
- `fp 139356…` (haproxy/ats) ⇒ `CL=[6],consumed=[6]` **vs** `CL=[3],consumed=[3]`.

⇒ Edge-coverage **mù** khi khác biệt nằm ở **giá trị số / độ dài** (không đổi nhánh code). Điểm mù này
**tái lập trên cả 3 proxy** ⇒ không phải artifact của một env hay của bản tái dựng, mà là **tính chất của
chính tín hiệu edge-coverage** — thứ HDHunter gốc cũng dựa vào. Đây là bằng chứng định lượng biện minh
hướng LLM Phase 2 (`docs/IDEA_llm_integration.md`).

---

## 8. Đối chiếu "Hạn chế" của v1

| Hạn chế trong v1 | Trạng thái v2 |
|---|---|
| Parser-internal state — "Chưa có" | ✅ **Có** trên 3/4 env (HttpParam 7-tuple thật) |
| Coverage-directed feedback — coverage.py xấp xỉ | ✅ **Witcher bitmap thật**, 99.9% case |
| Snapshot executor — `docker restart` | ◑ thay bằng **shm zero/request** |
| Exploit confirmation | ◻ vẫn cần replay/PoC (ngoài phạm vi) |
| Combined edge map proxy+backend | ◻ mới có backend (nginx/haproxy/ATS là C, chưa instrument) |

---

## 9. ⚠️ THỪA NHẬN: phần còn thiếu so với v1 (4 env)

v1 chạy **4 cặp**; v2 faithful chỉ phủ **3/4**. Phần thiếu được nêu thẳng:

### 9.1 Thiếu cặp **Apache HTTPD → Tomcat 10** (env thứ 4)
- Backend Tomcat là **Java** → không chạy được dưới Witcher-**python**. Faithful cho env này cần
  **Witcher-java** (`vendors/Witcher-java`, OpenJDK 11 vá, ghi `__AFL_SHM` cùng mô hình shm).
- Đã thử: cài build-deps, `configure` OK, vá `GenerateSources.gmk`. **Build `make images` không hoàn tất**:
  cây vendor là **patch-only** (đã strip build-tool upstream), vấp lần lượt (1) vardeps race GNU Make 4.3 ↔
  OpenJDK 11, (2) thiếu JFR generator, (3) thiếu tzdb/build-tool sources → whack-a-mole độ sâu không xác định.
- **Quyết định CHỐT: không faithful hoá Tomcat trong phạm vi đồ án.** Đây là **giới hạn công cụ, KHÔNG
  phải giới hạn phương pháp**: nếu có sẵn `bin/java` (`-XX:+WitcherInstrumentation`), pipeline hiện tại chỉ
  cần trỏ Tomcat dưới JDK đó với `__AFL_SHM` (ipc:host) là có coverage faithful hệt 3 env kia.
- **Đối chứng định tính vẫn còn:** Tomcat đã có data **black-box** ở v1 (`crash_reports_baseline_pre_*`,
  `crash_reports_run_1338`) — dùng tham chiếu nếu cần, nhưng **không** đưa vào bảng faithful.

### 9.2 Backend ATS bị đổi (gevent → gunicorn)
- Như §1: gevent (C-extension) cùng lớp rào cản với Tomcat. v2 giữ **proxy ATS thật** nhưng đổi backend
  sang gunicorn-under-Witcher. Ô ATS vì vậy so **tương đối** với v1, không phải so trực tiếp.

### 9.3 Response-side chưa faithful (còn black-box)
- Toàn bộ §2–§7 là **request-side**. Response-side (`fake_upstream` + so byte wire-level) **không có**
  coverage/HttpParam (đối tượng đo là response-parser của **proxy C**, chưa instrument). Trong các report
  response-side, mọi field `cov_*`/`*_real` đều `None`. Response-side chỉ giữ vai **breadth demo**, không
  đóng góp cho luận điểm điểm-mù.

> **Tóm lại phần thiếu:** 1 cặp faithful (Apache→Tomcat) — chặn bởi build Witcher-java; cộng thêm ATS đổi
> backend và response-side vẫn black-box. Cả ba đều là **rào cản công cụ trên WSL2 + cây vendor patch-only**,
> không phải sai phương pháp; pipeline sẵn sàng nhận chúng khi có runtime instrument tương ứng.

---

## 10. Hạn chế so với HDHunter paper

| Hạn chế | Trạng thái v2 |
|---|---|
| Engine fuzz | Tái lập **tín hiệu** coverage (R2), **không** dùng LibAFL/QEMU-Nyx (chặn trên WSL2). |
| Khớp số tuyệt đối Bảng 2 | Không claim — target (nginx/haproxy/ats + gunicorn) ≠ paper (Apache/Tomcat), quy mô 719 case. |
| Proxy coverage | nginx/haproxy/ATS là C, **chưa instrument** (cần `hdhunter-cc` clang-sancov + vá source — phase sau). |
| Exploit confirmation | Discrepancy là candidate; cần replay/tcpdump/PoC. |

---

## 11. Kết luận

1. Nâng từ baseline black-box (v1) lên **3 env faithful × 5 seed = 719 case**, **403 discrepancy (56.1%)**,
   coverage 99.9%, internal-state 7-tuple thật.
2. Hit-rate (56.1%) **sát v1 (58.2%)** ⇒ pipeline faithful tái lập đúng profile, thêm bằng chứng nội bộ.
3. **B6**: tỷ lệ desync framing THẬT khác rõ theo proxy (NGINX 63% > HAProxy 34% > ATS 26%).
4. **B8**: điểm mù "cùng edge khác consumed/CL" **tái lập trên cả 3 proxy** ⇒ tính chất chung của
   edge-coverage — bằng chứng định lượng cho hướng LLM (Phase 2).
5. **Phạm vi chốt = 3/4 env faithful.** Thiếu cặp Apache→Tomcat (chặn bởi Witcher-java build), ATS đổi
   backend, response-side còn black-box — tất cả là giới hạn công cụ, đã nêu thẳng ở §9.
6. **Hướng tiếp (Phase 2):** A/B ablation trên chính harness này (coverage-only vs +LLM) theo metric R8
   (time-to-first-discrepancy + số loại discrepancy trong các nhóm điểm-mù B8) → chứng minh LLM đóng được
   điểm mù; ngoại suy "cải thiện cho engine gốc" để ở mục Thảo luận như **giả thuyết có cơ sở** (vì điểm mù
   nằm ở tín hiệu coverage dùng chung).

---

## 12. Artifacts

| Artifact | Nội dung |
|---|---|
| `05_analyzer/trace_full_*.jsonl` | 15 file trace (3 env × 5 seed), 719 case — input cho B6/B8 |
| `05_analyzer/crash_reports_cov_full_*/` | report discrepancy có `cov_fingerprint` + `count/consumed_real` |
| `05_analyzer/run_witcher_full.sh` | driver tái lập toàn bộ |
| `05_analyzer/analyze_witcher_full.py` | aggregator §3–§7 |
| `05_analyzer/RESULT_witcher_full.md` | bản chi tiết kèm diễn giải (nguồn của file tổng hợp này) |
| `02_targets/{haproxy_flask,ats_gevent}/docker-compose.witcher*.yml` | pipeline faithful HAProxy / ATS→Gunicorn |
| `resultv1.md` | baseline trước refactor (935 report, 4 env, black-box) — để đối chứng |

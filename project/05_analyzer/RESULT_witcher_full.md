# BÁO CÁO THỰC NGHIỆM — Bản Witcher TOÀN DIỆN (coverage thật + internal-state thật, đa môi trường)

> Bản này **nâng quy mô** của `RESULT_witcher_b5.md` (chỉ 1 env, 1 seed, 48 case) lên **đúng phạm vi
> như `result.md` cũ**: nhiều môi trường × 5 RNG seed (1337–1341) × request-side — nhưng **mọi ô số liệu
> đều có coverage Witcher thật + HttpParam 7-tuple thật**, thứ mà `result.md` hoàn toàn không có.
> `result.md` là baseline cũ (935 report, 4 env, chỉ quan sát response, coverage.py xấp xỉ, không parser-state).

## 0. Phạm vi & cái đã nâng cấp

`result.md` chạy 4 env. Để chạy **faithful** (backend dưới Witcher-python → coverage bitmap interpreter-level
+ parser vá ghi HttpParam) thì backend phải là **Python thuần**. Bảng năng lực:

| Env trong `result.md` | Backend thật | Faithful-capable? | Trạng thái bản này |
|---|---|---|---|
| NGINX 1.25 → Gunicorn | gunicorn (Python) | ✅ | **Faithful** (đã có từ b5) |
| HAProxy 2.9 → Gunicorn | **gunicorn** (Python) | ✅ | **Faithful — MỚI** (dùng lại backend gunicorn-under-Witcher, proxy HAProxy 8890) |
| ATS → gevent | gevent (C-ext) | ⚠️ đổi backend | **Faithful dạng ATS→Gunicorn — MỚI** (xem dưới) |
| Apache HTTPD → Tomcat 10 | Tomcat (**Java**) | ❌ ngoài phạm vi (Witcher-java build không hoàn tất) | xem §9 |

**Vì sao ATS phải đổi backend:** `gevent` dựng trên C-extension (`greenlet`, `libev`, `c-ares`) phải biên dịch
ngược lại với interpreter Witcher tùy biến (CPython 3.7.9 ABI phi chuẩn: `abiflags` rỗng, không `pymalloc`,
thiếu `ssl`/pip-over-HTTPS). Đây **cùng loại rào cản với Tomcat (Java)**. Nên ATS proxy được trỏ vào **chính
backend gunicorn-under-Witcher** → env trở thành **ATS → Gunicorn**. Lợi: cô lập **biến PROXY** (ATS vs nginx vs
haproxy) trên cùng một backend đo đầy đủ. Hại: không còn khớp backend gevent của `result.md`.

- Nguồn số liệu: `05_analyzer/trace_full_<env>_<seed>.jsonl` (15 file = 3 env × 5 seed), tái lập bằng
  `05_analyzer/run_witcher_full.sh`; phân tích `05_analyzer/analyze_witcher_full.py`.
- **719 logical case** (3 env × 5 seed × 12 seed × ~4 variant; 1 case ats lỗi compose-timeout bị bỏ → 719/720).
- Mỗi case: backend gunicorn chạy **dưới Witcher-python** (bitmap 65536) + **parser vá** ghi HttpParam shm,
  runner đọc out-of-band (reset → proxy → đọc → reset → direct → đọc).

## 1. Cấu hình chạy

| Hạng mục | Giá trị |
|---|---|
| RNG seeds | 1337, 1338, 1339, 1340, 1341 |
| Env (faithful) | NGINX→Gunicorn, HAProxy→Gunicorn, ATS→Gunicorn (đều backend gunicorn-under-Witcher) |
| Request seeds | 12 golden HTTP request seeds |
| Mutations/seed | 3 + 1 original = 48 logical case / (env, seed) |
| Coverage | Witcher bitmap, reset/đọc out-of-band qua SysV shm mỗi request (R3) |
| Internal-state | HttpParam 7-tuple shm thật (B4b) |
| Snapshot/reset | shm zero trước mỗi request (thay `RESTART_EVERY=1` của bản cũ) |

Tái lập:
```bash
bash 05_analyzer/run_witcher_full.sh                 # 3 env × 5 seed
python3 05_analyzer/analyze_witcher_full.py 05_analyzer
```

## 2. Tổng quan & so sánh trực tiếp với `result.md`

| Chỉ số | `result.md` (cũ) | Bản Witcher toàn diện |
|---|---:|---:|
| Env faithful (coverage+state thật) | 0/4 | **3/4** (nginx, haproxy, ats→gunicorn) |
| Logical case request-side | 960 (4 env) | 719 (3 env faithful) |
| Discrepancies request-side | 559 (58.2%) | **403 (56.1%)** |
| Coverage fingerprint có mặt | ~0% (mostly null) | **718/719 (~100%)** |
| Parser-internal state thật | ❌ | ✅ (Count/Consumed/CL/chunked) |
| B6 lọc nhiễu / B8 điểm mù | ❌ | ✅ (xem §6–§7) |

Hit-rate tổng **56.1%** rất sát mức **58.2%** của `result.md` request-side ⇒ pipeline faithful **tái lập đúng
profile cũ**, đồng thời gắn thêm bằng chứng nội bộ cho từng discrepancy.

## 3. Request-side discrepancies theo env × seed

| Môi trường | s1337 | s1338 | s1339 | s1340 | s1341 | Tổng | Mean | Stddev | Hit rate | `result.md` (cũ) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| NGINX 1.25 → Gunicorn | 32 | 38 | 34 | 32 | 31 | **167** | 33.4 | ±2.50 | 69.6% | 165 (68.8%) |
| HAProxy 2.9 → Gunicorn | 21 | 25 | 26 | 18 | 28 | **118** | 23.6 | ±3.61 | 49.2% | 121 (50.4%) |
| ATS → Gunicorn (gevent đã đổi) | 23 | 25 | 21 | 23 | 26 | **118** | 23.6 | ±1.74 | 49.4% | 126 (52.5%)¹ |
| **Tổng** | 76 | 88 | 81 | 73 | 85 | **403** |  |  | **56.1%** | 559 (58.2%, 4 env) |

¹ Ô `result.md` cũ là ATS→**gevent**; bản này là ATS→**gunicorn** nên chỉ so tương đối (cùng proxy ATS, khác backend).

NGINX gần như trùng khít (167 vs 165). HAProxy sát (118 vs 121). ⇒ con số faithful ổn định, không phải nhiễu.

## 4. Rule frequency theo env (5 seed)

| Môi trường | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | R9 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| NGINX → Gunicorn | 64 | 64 | 110 | 93 | 49 | 73 | 160 | 124 | 22 |
| HAProxy → Gunicorn | 45 | 45 | 30 | 27 | 44 | 21 | 106 | 57 | 38 |
| ATS → Gunicorn | 29 | 29 | 30 | 18 | 42 | 13 | 73 | 44 | 28 |

R7 (`raw_response_length`) vẫn nhiều nhất ở mọi env — đúng cảnh báo "tín hiệu rộng, cần replay" của `result.md` §5;
nay được B6 (§6) lọc lại bằng state thật. R8 mạnh trên NGINX (124) khớp nhận xét `result.md` về order-oracle.

## 5. Mutation distribution (total / tạo discrepancy)

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
| (còn lại) | ≤23 mỗi loại | — |

Giống `result.md` §9: `original` + `sequence:*` đóng góp nhiều nhất (golden seed vốn là edge-case HTTP/1.1).

## 6. [MỚI] B6 — internal-state corroboration (lọc nhiễu tầng-quan-sát)

Dùng state THẬT 2 phía hỏi: discrepancy có được parse-state nội bộ xác nhận (proxy-parse ≠ direct-parse)?

| Môi trường | Disc | Có divergence state THẬT | Response-observation-only |
|---|---:|---:|---:|
| NGINX → Gunicorn | 167 | **106 (63%)** | 61 (37%) |
| HAProxy → Gunicorn | 118 | **40 (34%)** | 78 (66%) |
| ATS → Gunicorn | 118 | **31 (26%)** | 87 (74%) |

→ Định lượng được lần đầu: tỷ lệ "nhiễu tầng-quan-sát" khác nhau rõ theo proxy — **NGINX desync framing thật
nhiều nhất (63%)**, còn HAProxy/ATS phần lớn discrepancy chỉ ở tầng wire/forwarding (cần replay). Đây là kết
luận mà `result.md` (không có state) không thể đưa ra.

## 7. [MỚI] B8 — điểm mù coverage (deliverable học thuật chính)

Gom case theo `cov_fingerprint` (direct), tìm nhóm **cùng tập edge** nhưng **state THẬT khác**:

| Môi trường | Nhóm fingerprint mù |
|---|---:|
| NGINX → Gunicorn | 5 |
| HAProxy → Gunicorn | 5 |
| ATS → Gunicorn | 5 |

Ví dụ (lặp lại nhất quán trên cả 3 env):
- `fp 3d0577…` (cùng edge, `chunked=True`) ⇒ `consumed_real=[5]` **vs** `[11]`.
- `fp 9a728f…` ⇒ `CL=[6],consumed=[6]` **vs** `CL=[11],consumed=[11]`.
- `fp 139356…` (haproxy) ⇒ `CL=[6]` **vs** `[3]`.

⇒ Edge-coverage **mù** khi khác biệt nằm ở **giá trị số / độ dài** (không đổi nhánh code). Điểm mù này **tái lập
trên cả 3 proxy** ⇒ không phải đặc thù một env, mà là tính chất của edge-coverage — bằng chứng định lượng cho
hướng LLM Phase 2 (`docs/IDEA_llm_integration.md`).

## 8. Đối chiếu "Hạn chế" của `result.md` §10

| Hạn chế cũ | Trạng thái bản này |
|---|---|
| Parser-internal state — "Chưa có" | ✅ **Có** trên 3/4 env (HttpParam 7-tuple thật) |
| Coverage-directed feedback — coverage.py xấp xỉ | ✅ **Witcher bitmap thật**, ~100% case |
| Snapshot executor — `docker restart` | ◑ thay bằng **shm zero/request** |
| Exploit confirmation | ◻ vẫn cần replay/PoC (ngoài phạm vi) |
| Combined edge map proxy+backend | ◻ mới backend (nginx/haproxy/ATS là C, chưa instrument) |

## 9. Tomcat / Witcher-java (env thứ 4)

Backend Tomcat là **Java** → không chạy được dưới Witcher-python. Faithful cho env này cần **Witcher-java**
(`vendors/Witcher-java` = OpenJDK 11 vá, hook `-XX:+WitcherInstrumentation` ghi `__AFL_SHM`, cùng mô hình shm).
Bản này đã: cài build-deps, `configure` OK (`11-Witcher1-internal`), vá `make/hotspot/gensrc/GenerateSources.gmk`.

**Trạng thái build (CHỐT — KHÔNG hoàn tất trong phạm vi đồ án):** cây vendor `Witcher-java` là **patch-only**
(đã bị strip các thư mục build-tool upstream: `make/src/classes`, `make/jdk/src/classes`,
`make/langtools/src/classes`, `make/hotspot/src/classes`). Build `make images` lần lượt vấp:
(1) **vardeps race** của GNU Make 4.3 ↔ OpenJDK 11 (`$(file >)` parse-time không được sub-make song song
thấy là prereq) — xử lý bằng cách lặp `make images`; (2) thiếu **JFR generator** (`GenerateJfrFiles.java`);
(3) thiếu **build-tool sources** khác, gần nhất là `tzdb` (`TzdbZoneRulesProvider.java` `import
build.tools.tzdb.ZoneOffsetTransitionRule` — thiếu loạt sibling `ZoneOffsetTransitionRule.java`,
`ZoneRules.java`, `ZoneOffsetTransition.java`, `ZoneRulesBuilder.java`...). Mỗi vòng cần fetch thêm source
upstream → whack-a-mole độ sâu không xác định. **Quyết định:** dừng tại đây, **không faithful hoá Tomcat**.

**Phân loại:** Tomcat (Java) thuộc **cùng lớp rào cản với gevent** (C-extension) — đều cần một **runtime đã
được instrument đúng ABI** (Witcher-java cho JVM, build C-ext khớp ABI cho gevent) mà môi trường WSL2 + cây
vendor strip không dựng được trong ngân sách đồ án. Đây là **giới hạn công cụ, không phải giới hạn phương pháp**:
nếu có sẵn `bin/java` (`-XX:+WitcherInstrumentation`), pipeline hiện tại chỉ cần trỏ Tomcat dưới JDK đó với
`__AFL_SHM` (ipc:host) là có coverage faithful, hệt 3 env kia; internal-state HttpParam cho Java sẽ cần
javaagent/patch Coyote Http11. **3/4 env faithful là phạm vi chốt của báo cáo này.**

## 10. Kết luận

1. Nâng từ 1 env/1 seed (b5) lên **3 env faithful × 5 seed = 719 case**, **403 discrepancy (56.1%)**, coverage ~100%.
2. Hit-rate (56.1%) sát `result.md` (58.2%) ⇒ pipeline faithful tái lập đúng profile, có thêm bằng chứng nội bộ.
3. **B6**: tỷ lệ desync framing THẬT khác rõ theo proxy (NGINX 63% > HAProxy 34% > ATS 26%).
4. **B8**: điểm mù "cùng edge khác consumed/CL" tái lập trên cả 3 proxy ⇒ tính chất chung của edge-coverage.
5. **Phạm vi chốt = 3/4 env faithful.** Tomcat (Java) và gevent (C-ext) bị chặn bởi cùng một lớp rào cản
   *công cụ* — cần runtime instrument đúng ABI mà WSL2 + cây vendor patch-only không dựng nổi trong ngân sách
   (chi tiết §9). Không phải giới hạn phương pháp: pipeline sẵn sàng nhận cả hai khi có runtime tương ứng.

## 11. Artifacts

| Artifact | Nội dung |
|---|---|
| `05_analyzer/trace_full_*.jsonl` | 15 file trace (3 env × 5 seed), input cho B6/B8 |
| `05_analyzer/crash_reports_cov_full_*/` | report discrepancy có cov_fingerprint + count/consumed_real |
| `05_analyzer/run_witcher_full.sh` | driver tái lập toàn bộ |
| `05_analyzer/analyze_witcher_full.py` | aggregator §3–§7 |
| `02_targets/haproxy_flask/docker-compose.witcher.yml` + `.override.yml` | pipeline faithful HAProxy |
| `02_targets/ats_gevent/docker-compose.witcher.yml` + `.override.yml` | pipeline faithful ATS→Gunicorn |

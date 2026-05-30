# BAO CAO THUC NGHIEM - HDHUNTER-Inspired Differential Testbed

## 0. Pham vi so lieu

- Nguon so lieu: `05_analyzer/crash_reports_run_1337` den `05_analyzer/crash_reports_run_1341`.
- Khong tinh `05_analyzer/crash_reports/` hien hanh vi thu muc nay co the chua report con sot tu luot chay bi ngat hoac chay thu.
- Tong report discrepancy hop le trong archive: **935**.

## 1. Cau hinh chay

| Hang muc | Gia tri |
|---|---|
| RNG seeds | 1337, 1338, 1339, 1340, 1341 |
| Target environments | NGINX/Gunicorn, HAProxy/Gunicorn, ATS/gevent, Apache/Tomcat |
| Request seeds | 12 golden HTTP request seeds |
| Response seeds | 5 malformed HTTP response seeds |
| Mutations/seed | 3 mutations + 1 original |
| Snapshot/reset | `RESTART_EVERY=1` cho ca request-side va response-side |
| Request-side expected | 4 env x 5 seeds x 12 request seeds x 4 variants = 960 tests |
| Response-side expected | 4 env x 5 seeds x 5 response seeds x 4 variants = 400 tests |
| Tong expected | **1360 logical tests** |

Reproduce command:

```bash
time RNG_SEEDS="1337 1338 1339 1340 1341" \
MUTATIONS=3 \
RESTART_EVERY=1 \
bash run_paper_style_experiment.sh 2>&1 | tee outputs/paper_style_experiment_full.log
```

## 2. Tong quan ket qua

| Nhom test | Discrepancies | Expected tests | Hit rate |
|---|---:|---:|---:|
| Request-side | 559 | 960 | 58.2% |
| Response-side | 376 | 400 | 94.0% |
| **Tong** | **935** | **1360** | **68.8%** |

Dien giai: hit rate la ti le test tao ra discrepancy report, **khong phai** ti le lo hong. Discrepancy chi la tin hieu can replay, tcpdump/wire-tap va chung minh security impact.

## 3. Request-side results

| Moi truong | s1337 | s1338 | s1339 | s1340 | s1341 | Tong | Mean | Stddev | Hit rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| NGINX 1.25 -> Gunicorn | 28 | 38 | 36 | 33 | 30 | 165 | 33.0 | +/-3.69 | 68.8% |
| HAProxy 2.9 -> Gunicorn | 30 | 22 | 26 | 19 | 24 | 121 | 24.2 | +/-3.71 | 50.4% |
| ATS -> gevent | 23 | 23 | 28 | 23 | 29 | 126 | 25.2 | +/-2.71 | 52.5% |
| Apache HTTPD -> Tomcat 10 | 28 | 30 | 35 | 28 | 26 | 147 | 29.4 | +/-3.07 | 61.3% |
| **Tong request-side** | 109 | 113 | 125 | 103 | 109 | **559** | **111.8** | +/-7.33 | **58.2%** |

Nhan xet chinh:

- NGINX/Gunicorn co hit rate request-side cao nhat: 165/240 = 68.8%.
- HAProxy/Gunicorn tang len 121 reports so voi bao cao cu, chu yeu do restart moi test lam trang thai sach hon.
- ATS/gevent van co diversity cao nhat, phu hop de chon replay sau.
- Apache/Tomcat co it smuggling-count mismatch nhung nhieu tin hieu TE/CL/content mismatch.

## 4. Response-side results

| Moi truong | s1337 | s1338 | s1339 | s1340 | s1341 | Tong | Mean | Stddev | Hit rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| NGINX 1.25 -> Gunicorn | 19 | 19 | 19 | 20 | 20 | 97 | 19.4 | +/-0.49 | 97.0% |
| HAProxy 2.9 -> Gunicorn | 20 | 20 | 20 | 20 | 20 | 100 | 20.0 | +/-0.00 | 100.0% |
| ATS -> gevent | 16 | 17 | 16 | 15 | 15 | 79 | 15.8 | +/-0.75 | 79.0% |
| Apache HTTPD -> Tomcat 10 | 20 | 20 | 20 | 20 | 20 | 100 | 20.0 | +/-0.00 | 100.0% |
| **Tong response-side** | 75 | 76 | 75 | 75 | 75 | **376** | **75.2** | +/-0.40 | **94.0%** |

Nhan xet chinh:

- HAProxy va Apache dat 100/100 response-side: moi response seed/mutation deu tao discrepancy quan sat duoc.
- NGINX dat 97/100, chi co 3 case khong tao discrepancy.
- ATS thap hon ro ret o response-side: 79/100, tuc co nhieu case proxy/client output gan voi fake upstream hon.
- Response-side discrepancy can dien giai can than: day co the la forwarding/sanitization/normalization khac nhau, chua tu dong dong nghia voi exploit.

## 5. Rule frequency

| Rule | Field | Request-side | Response-side | Tong |
|---|---|---:|---:|---:|
| R1 | `observed_response_count` | 165 | 87 | 252 |
| R2 | `observed_messages_parsed` | 165 | 87 | 252 |
| R3 | `status` | 256 | 244 | 500 |
| R4 | `transfer_encoding` | 221 | 0 | 221 |
| R5 | `content_length` | 147 | 0 | 147 |
| R6 | `body_length` | 143 | 0 | 143 |
| R7 | `raw_response_length` | 416 | 364 | 780 |
| R8 | `response_order` | 250 | 0 | 250 |
| R9 | `body_hash` | 63 | 0 | 63 |

Rule theo request-side tung moi truong:

| Moi truong | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | R9 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| NGINX 1.25 -> Gunicorn | 70 | 70 | 106 | 90 | 45 | 71 | 157 | 119 | 22 |
| HAProxy 2.9 -> Gunicorn | 47 | 47 | 75 | 39 | 5 | 31 | 81 | 77 | 25 |
| ATS -> gevent | 44 | 44 | 55 | 18 | 26 | 41 | 83 | 51 | 16 |
| Apache HTTPD -> Tomcat 10 | 4 | 4 | 20 | 74 | 71 | 0 | 95 | 3 | 0 |

Nhan xet rule:

- R7 `raw_response_length` van la rule nhieu nhat, nen phai xem day la tin hieu rong va can replay xac nhan.
- R8 `response_order` rat manh tren NGINX request-side: 119 lan, cho thay order oracle bang `X-Desync-Id` co dong gop ro.
- R9 `body_hash` bat duoc 63 truong hop content khac nhau du length co the khong du bieu dien khac biet.
- Response-side chu yeu kich hoat R1/R2/R3/R7; cac rule WSGI/CGI nhu R4-R6/R8/R9 khong co nhieu y nghia trong mode response vi ground truth la raw fake upstream response.

## 6. Confidence va stability

| Request-side moi truong | High | Low | % Low |
|---|---:|---:|---:|
| NGINX 1.25 -> Gunicorn | 165 | 0 | 0.0% |
| HAProxy 2.9 -> Gunicorn | 109 | 12 | 9.9% |
| ATS -> gevent | 87 | 39 | 31.0% |
| Apache HTTPD -> Tomcat 10 | 112 | 35 | 23.8% |

Low confidence nghia la co `partial_timeout=True`; khi do R7 da bi suppress trong detector, nhung cac tin hieu con lai van nen replay. ATS va Apache/Tomcat co low-confidence cao hon do keep-alive/timeout behavior dai hon.

## 7. Diversity va attack candidates

| Moi truong | Request signatures | Response signatures |
|---|---:|---:|
| NGINX 1.25 -> Gunicorn | 14 | 5 |
| HAProxy 2.9 -> Gunicorn | 18 | 5 |
| ATS -> gevent | 21 | 4 |
| Apache HTTPD -> Tomcat 10 | 7 | 5 |

| Nhom candidate | Request-side | Response-side | Tong |
|---|---:|---:|---:|
| Request Smuggling candidate | 165 | 87 | 252 |
| Request Confusing candidate | 243 | 192 | 435 |
| Response Stealing/Forgery candidate | 151 | 97 | 248 |

Luu y: cac nhan candidate duoc suy ra heuristic tu rule set, khong phai bang chung khai thac. Muon nang len vulnerability phai replay persistent connection va chung minh request/response queue bi chiem hoac policy bi bypass.

## 8. Triage.py classification

Phan nay tong hop theo dung logic classification trong `05_analyzer/triage.py`, nhung chi chay tren archive sach `crash_reports_run_1337..1341`.

### 8.1 Taxonomy (Desync Shapes)

| Triage label | Reports | Ti le |
|---|---:|---:|
| Response-side: length/order discrepancy | 488 | 52.2% |
| Possible Request-side Desync: paths emitted different numbers of HTTP responses | 252 | 27.0% |
| Possible Request-side Desync: response content/length differs | 195 | 20.9% |

### 8.2 Primary Discrepancies

| Triage label | Reports | Ti le |
|---|---:|---:|
| Incomplete response sanitization (Validation Bypass) | 372 | 39.8% |
| Incomplete response sanitization (Raw byte difference) | 285 | 30.5% |
| Non-standard number parsing | 204 | 21.8% |
| Differing TE.CL handling strategies | 44 | 4.7% |
| Other | 21 | 2.2% |
| Inconsistent trailer section handling | 9 | 1.0% |

### 8.3 Attack Candidates

| Triage label | Reports | Ti le |
|---|---:|---:|
| Request Confusing candidate (requires semantic validation) | 435 | 46.5% |
| Request Smuggling candidate (requires replay/PoC) | 252 | 27.0% |
| Response Stealing/Forgery candidate (requires response-queue PoC) | 248 | 26.5% |

### 8.4 Insights

| Triage label | Reports | Ti le |
|---|---:|---:|
| Programming language quirks (Number Parsing routines) | 431 | 46.1% |
| Protocol translation issues (Proxy vs WSGI/CGI Mismatch) | 430 | 46.0% |
| Non-standard HTTP RFC compliance | 57 | 6.1% |
| Rarely-used feature handling (Trailer Sections) | 17 | 1.8% |

### 8.5 Triage note

- `triage.py` la heuristic classifier, khong phai exploit verifier.
- Cac nhom "Request Smuggling", "Request Confusing", va "Response Stealing/Forgery" la danh sach uu tien de replay.
- Section repeat stability cua `triage.py` hien can doc can than: request-side report co repeat metadata that, con response-side report dang luu `mode=response` trong cung field `repeat_analysis`, nen khong nen dung truc tiep de ket luan stability cho response-side.

## 9. Mutation distribution

| Mutation label | Reports |
|---|---:|
| `original` | 229 |
| `sequence:splice` | 101 |
| `byte:inject_smuggling_prefix` | 64 |
| `byte:perturb_content_length` | 62 |
| `byte:obfuscate_whitespace` | 61 |
| `sequence:remove` | 55 |
| `byte:obfuscate_transfer_encoding` | 47 |
| `byte:byte_remove` | 45 |
| `byte:byte_splice` | 42 |
| `byte:byte_duplicate` | 36 |
| `message:node_typed_swap` | 32 |
| `byte:obfuscate_unicode_encoding` | 28 |
| `byte:byte_insert` | 28 |
| `message:node_token_replace` | 25 |
| `message:field_line_duplicate` | 22 |
| `byte:splice` | 18 |
| `message:trailer_section_replace` | 17 |
| `message:field_line_splice` | 14 |
| `message:field_line_remove` | 9 |

Diem dang chu y la `original` cung tao nhieu discrepancy. Dieu nay khong sai: nhieu golden seeds von da la cac edge case HTTP/1.1 mo ho nhu duplicate CL, TE.CL, CL.TE, trailer va pipelining.

## 10. Han che so voi HDHUNTER paper

| Han che | Trang thai trong project |
|---|---|
| Parser-internal state | Chua co; detector dung observed response tuple va JSON do backend expose. |
| Coverage-directed feedback | Co approximation o backend Python bang coverage.py; chua co combined edge map cua proxy + backend. |
| Snapshot executor | Dung `docker compose restart`, khong phai QEMU snapshot/restore. |
| Exploit confirmation | Discrepancy moi la candidate; can replay/tcpdump/PoC de chung minh security impact. |
| Response-side oracle | So sanh raw fake upstream response voi output qua proxy; de bat normalization khac nhau, can phan tich thu cong. |
| Tomcat state enrichment | JSP backend thieu mot so field enriched nhu WSGI body_hash/wsgi_eof day du. |

## 11. Ket luan

1. Full run sach theo 5 RNG seeds tao ra **935 discrepancies / 1360 tests = 68.8%**.
2. Request-side dat **559 / 960 = 58.2%**; response-side dat **376 / 400 = 94.0%**.
3. Restart moi logical test cho ca request-side va response-side giup ket qua dang tin hon so voi cau hinh cu restart moi 24 test.
4. NGINX noi bat o R8 response order; ATS co request-side signature diversity cao nhat; HAProxy va Apache noi bat o response-side 100%.
5. Buoc tiep theo nen chon top candidates co R1/R2/R8/R9, replay tren persistent connection, bat wire-tap/tcpdump giua proxy va backend, roi moi ket luan vulnerability.

## 12. Artifacts

| Artifact | Noi dung |
|---|---|
| `05_analyzer/crash_reports_run_1337/` | 184 discrepancy JSON reports |
| `05_analyzer/crash_reports_run_1338/` | 189 discrepancy JSON reports |
| `05_analyzer/crash_reports_run_1339/` | 200 discrepancy JSON reports |
| `05_analyzer/crash_reports_run_1340/` | 178 discrepancy JSON reports |
| `05_analyzer/crash_reports_run_1341/` | 184 discrepancy JSON reports |
| `outputs/paper_style_experiment_full.log` | Log chay full experiment |
| `05_analyzer/triage_all_runs.txt` | Co the bi lan report cu neu scan ca `05_analyzer`; report nay dung archive clean o `crash_reports_run_*`. |


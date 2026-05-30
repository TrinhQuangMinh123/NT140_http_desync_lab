# THẢO LUẬN — Ý tưởng tích hợp LLM (Phase 2)

> File chốt ý tưởng lớn đã bàn. **Chưa phải spec.** Mục tiêu: ghi lại lập luận trung tâm,
> các invariant bắt buộc, bản đồ trục thiết kế, và câu hỏi còn mở — để khi vào Phase 2 không bàn lại từ đầu.
> Liên quan: `PLAN_phase1_coverage.md` (điều kiện tiên quyết), `REPO_UPSTREAM_NOTES.md` (rules).

---

## 1. Lập luận trung tâm (chỗ LLM mới ăn tiền)

Coverage feedback là **prior tất định**, nhưng có **điểm mù**: các discrepancy chạm **CÙNG branch
với GIÁ TRỊ khác nhau** → không sinh edge mới → gradient coverage = 0 → fuzzer coverage-guided
không được dẫn tới đó.

Ví dụ kinh điển — **Number Parsing**: `Content-Length: 10` vs `Content-Length: 0x10`.
Một bên parse bằng `strtoul`/`int()` (chấp nhận/diễn giải khác), bên kia dùng vòng lặp digit thủ công
→ hai bên hiểu độ dài body khác nhau (desync THẬT), nhưng **đi qua cùng tập edge** → coverage mù hoàn toàn.
Paper §6.2 cũng chỉ ra root cause: developer dựa vào parser built-in.

**Vai trò LLM:** đọc code parse HTTP của **CẢ proxy lẫn backend**, phát hiện các điểm **phân kỳ ngữ nghĩa
liên-cài-đặt** mà coverage không biểu diễn được, rồi **thiên lệch (bias) việc sinh biến thể** về phía đó —
**KHÔNG** vào hot loop.

Tên làm việc: **Differential Parser-Aware Fuzzing**.

---

## 2. Invariant BẮT BUỘC (điều kiện để ý tưởng đứng vững)

- **I1 — LLM ngoài hot loop.** LLM chạy offline/amortized; vòng fuzz chỉ đọc artifact tĩnh. Giữ exe/s.
- **I2 — Prior MỀM.** Output LLM chỉ *thiên lệch* phân bố mutation, **không bao giờ loại trừ** vùng nào
  (chống hallucination: LLM đoán sai thì cùng lắm phí ngân sách, không bịt mất vùng đúng).
- **I3 — Tất định & tái lập.** Đóng băng output LLM thành **artifact tĩnh**, cache lại, pin temperature.
  Vòng fuzz phải reproducible.
- **I4 — Phải chứng minh bằng ABLATION.** Sống/chết bằng A/B: cùng ngân sách, cùng seed, so
  *có-LLM-prior* vs *không* trên metric R8 (time-to-first-discrepancy, số loại discrepancy). Không có ablation = không có claim.
- **I5 — Chỉ tính điểm ở blind spot.** LLM chỉ kỳ vọng thắng ở đúng vùng coverage mù (same-branch-diff-value).
  Ở vùng coverage đã dẫn tốt, LLM không nên can thiệp.

---

## 3. Bản đồ trục thiết kế (mức ý tưởng — chưa chốt)

- **Trục 0 — Regime.** ✅ Đã giải: gray-box-trên-coverage KHẢ THI (Witcher-python, không QEMU).
  Phase 1 dựng coverage này.
- **Trục 1 — VAI TRÒ LLM (ngã ba lớn nhất, CÒN MỞ).**
  - (a) **Chủ động — đạo diễn đầu vào**: LLM lái việc *sinh* biến thể về điểm phân kỳ.
  - (b) **Bị động — lọc/xác minh đầu ra**: LLM gác cổng dòng candidate, loại nhiễu, phân loại.
  - (c) **Cả hai.**
  - *Ghi chú:* dữ liệu crash-report cho thấy tool hiện cũng có bài toán nhiễu lớn → (b) đáng cân nhắc;
    nhưng sau khi có coverage thật (Phase 1), nhiễu có thể giảm mạnh → cân lại.
- **Trục 2 — LÚC NÀO.** Offline trước chiến dịch / giữa loop định kỳ / phản ứng theo sự kiện.
  ❌ KHÔNG bao giờ mỗi execution (I1).
- **Trục 3 — CẮM VÀO ĐÂU.** Corpus seed / từ điển token / bộ chọn operator của mutator / scheduler / detector-triage.
- **Trục 4 — ĐỌC GÌ → XUẤT GÌ.** Input: code 2 parser / feedback runtime / RFC. Output: seed / token /
  **trọng số policy** / verdict thật-giả. Output phải ánh xạ xuống thứ hệ thống hiện hiểu được.
- **Trục 5 — HÒA TRỘN.** Prior LLM trộn với coverage thế nào (cộng trọng số / epsilon-greedy / phân rã thời gian).
- **Trục 6 — GRANULARITY.** Theo từng **cặp target** (proxy↔backend) / theo feature parser.

---

## 4. Hình hài cụ thể đang nghiêng về (giả định để bàn tiếp, chưa chốt)

> Trục 1 = (a) chủ động; Trục 2 = offline; Trục 3 = từ điển token + trọng số mutation; Trục 6 = per-target-pair.

1. **Offline (một lần / mỗi cặp target):** LLM đọc code parse HTTP của proxy & backend →
   xuất tập **"giả thuyết phân kỳ"** (vd: "CL dạng hex", "TE có khoảng trắng trước dấu hai chấm",
   "chunk-size dạng số âm"…), mỗi cái kèm **token/biến thể gợi ý** + **trọng số**.
2. **Đóng băng** thành artifact tĩnh (JSON) — cache, reproducible (I3).
3. Vòng fuzz đọc artifact → **thiên lệch mềm** phân bố mutation/từ điển về các điểm đó (I2),
   trộn với coverage feedback (Trục 5).
4. **Ablation** (I4): A/B vs baseline coverage-only trên metric R8.

---

## 5. Câu hỏi CÒN MỞ (giải ở đầu Phase 2)

- **Q1 — Trục 1:** chốt chủ động vs bị động vs cả hai (cân lại sau khi Phase 1 cho biết nhiễu còn bao nhiêu).
- **Q2 — Schema artifact "giả thuyết phân kỳ":** gồm field gì? ánh xạ xuống mutator/từ điển ra sao?
- **Q3 — Cơ chế trộn prior↔coverage (Trục 5):** công thức cụ thể, có phân rã theo thời gian không?
- **Q4 — Thiết kế ablation:** baseline nào, ngân sách bao nhiêu, bao nhiêu lần lặp để có ý nghĩa thống kê?
- **Q5 — Chống hallucination thực tế:** đo gì để biết LLM đoán sai không gây hại?

---

## 6. Điều kiện TIÊN QUYẾT trước khi viết spec Phase 2

**B8 của Phase 1 phải cho bằng chứng điểm mù tồn tại thật**: đếm số ca
**(desync state khác nhau) ∧ (cov_fingerprint giống hệt)**. Nếu con số này ~0 → coverage KHÔNG mù trên
target này → ý tưởng LLM-prior mất cơ sở, phải đổi hướng (vd sang vai trò lọc/xác minh — Trục 1b).
Nếu đáng kể → có cây cầu chính đáng sang Phase 2.

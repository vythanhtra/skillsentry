# So sánh SkillSentry với các repo bảo mật nổi tiếng

## Phạm vi đánh giá
Báo cáo này đánh giá repo `skillsentry` theo các tiêu chí phổ biến của công cụ security scanning:
- Mục tiêu sản phẩm
- Kiến trúc kỹ thuật
- Tính năng phát hiện
- DX (developer experience)
- Mức sẵn sàng production

## Tóm tắt nhanh
- **Điểm mạnh nổi bật**: tập trung rất đúng vào bài toán mới (AI skill file security), luật phát hiện đa lớp, chạy zero-dependency rất dễ triển khai.
- **Khoảng cách so với các repo top thế giới**: thiếu test suite/CI rõ ràng, thiếu benchmark định lượng, chưa có hệ plugin/rulepack/community signals.

## So sánh theo nhóm repo nổi tiếng

### 1) So với Gitleaks / TruffleHog / detect-secrets (secret scanning)
**SkillSentry mạnh hơn ở ngữ cảnh AI skill**
- Có behavior chain (kết hợp hành vi) thay vì chỉ match secret pattern đơn lẻ.
- Có prompt-injection detection và evasions (homoglyph/zero-width/base64), đây là khác biệt quan trọng.

**SkillSentry yếu hơn ở maturity sản phẩm**
- Chưa thấy baseline suppression workflow lớn như detect-secrets.
- Chưa có ecosystem rulepacks/community + integrations rộng như các tool lâu năm.
- Chưa có benchmark public lớn về precision/recall trên dữ liệu thực chiến.

### 2) So với Semgrep (SAST rule engine)
**SkillSentry có lợi thế focus domain**
- Không cố giải bài toán code analysis tổng quát; tập trung vào content-level skill security nên gọn và dễ dùng.
- Rule YAML + engine Python đơn file giúp onboarding rất nhanh.

**Khoảng cách so với Semgrep**
- Chưa có parser/AST-level semantics đa ngôn ngữ.
- Chưa có rule test harness/phân phối rule versioning ở mức enterprise.
- Chưa có cloud triage/workflow management.

### 3) So với Guardrails/Prompt-security projects
**SkillSentry nổi bật**
- Kết hợp cả command-risk + prompt-injection trong cùng pipeline.
- Có scoring + alert webhook (Discord/Telegram), hữu ích cho vận hành.

**Cần cải thiện**
- Thiếu bộ dữ liệu chuẩn cho prompt injection regression tests.
- Thiếu chế độ explainability sâu hơn (vì sao rule match, confidence calibration).

## Đánh giá theo tiêu chí kỹ thuật

### A. Product positioning
- Định vị rõ ràng: “AI Skill Security Scanner”, mô tả rõ threat model (exfiltration, obfuscation, injection).
- Thích hợp cho giai đoạn pre-install gate của agent skills.

### B. Architecture
- Engine Python ~800 dòng, dễ audit, dễ đóng gói nội bộ.
- Rule ngoài YAML giúp mở rộng nhanh.
- Trade-off: kiến trúc đơn khối, khi scale rule + multi-format có thể khó bảo trì hơn kiến trúc module/plugin.

### C. Detection depth
- Có 9 lớp phân tích; điểm cộng lớn là behavior chains + evasions.
- Có decode base64 và URL risk heuristics.
- Điểm cần tăng: scoring calibration và false-positive controls theo môi trường thực tế.

### D. DevEx & Ops
- Ưu: zero dependency, CLI đơn giản, có JSON output, có webhook alert.
- Cần thêm: GitHub Action chính thức, pre-commit hook, SARIF output để tích hợp code scanning ecosystem.

### E. Trust signals (so với world-class repos)
Để tiệm cận repo nổi tiếng toàn cầu, nên bổ sung:
1. CI matrix + unit/integration tests + coverage badge.
2. Benchmark public (dataset benign/malicious) và báo cáo precision/recall.
3. Versioned rulepacks + changelog semantic rõ ràng.
4. Security policy, disclosure process, signed releases.
5. Contributor guide và roadmap công khai.

## Xếp hạng thực tế (quan điểm kỹ thuật)
- **Ý tưởng & đúng nhu cầu thị trường AI agent**: 8.5/10
- **Độ sâu kỹ thuật hiện tại**: 7.5/10
- **Maturity so với repo top global**: 5.5/10
- **Tiềm năng 6–12 tháng nếu đầu tư đúng**: 9/10

## Kết luận
SkillSentry hiện giống một **“strong specialized security tool”** hơn là một “ecosystem project” cỡ Semgrep/Gitleaks.
Nếu mục tiêu là bảo vệ chuỗi cài đặt AI skills cho team nhỏ-vừa, repo này đã rất hữu dụng. Để cạnh tranh tầm quốc tế, cần đầu tư mạnh vào test/benchmark/integrations/community.

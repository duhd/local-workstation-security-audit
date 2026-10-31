# Changelog

Mọi thay đổi đáng chú ý của skill này được ghi ở đây.
Định dạng theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/); phiên bản theo [SemVer](https://semver.org/lang/vi/).

## [1.0.0] — 2026-10-31

Bản phát hành đầu tiên.

### Thêm

- **17 phase audit** cho Windows / macOS / Linux, chia 2 tầng:
  - Phase 1–9 (posture): patch OS, mã hoá ổ, TPM/Secure Boot/SIP, firewall + listener + ACL mạng overlay, credential at-rest, persistence, browser profile/extension/remote-access host, repo & lịch sử git, patch gap ứng dụng, severity, remediation, report.
  - Phase 10–17 (attacker-first): danh tính & vật liệu phiên, thực thi code & leo thang đặc quyền, secret trong artifact/backup/cloud sync, kênh tin cậy & certificate store, năng lực phát hiện, mạng ngoài listener, vật lý/pre-boot, bề mặt AI agent.
- **Patch gap + CVE mapping** (Phase 1): so version đang cài với bản stable mới nhất; đối chiếu CVE cho nhóm rủi ro cao qua NVD / MSRC / OSV / GHSA, enrich bằng EPSS.
- **Pipeline kiểu Grype cho máy trạm**: catalog (SBOM-lite) → match có version constraint → enrich (EPSS; KEV nếu truy cập được) → policy/VEX có `expires` → output tái lập kèm `fix.state`.
- **Chạy multi-subagent**: 4 slice độc lập A–D, tối đa 4 agent đồng thời, kèm hợp đồng 7 điều bắt buộc cho subagent và trách nhiệm của parent (dedupe, chuẩn hoá severity, coverage ledger).
- **Luật bằng chứng**: mỗi phép đo có positive control; phân biệt *đã kiểm sạch* / *có vấn đề* / **chưa kiểm được**; verify bằng state thay vì exit code; đo lại sau khi sửa.
- **Bảng 16 bẫy đã cắn thật** — false negative do filter hẹp, `ls -la` trong MSYS, output bị redact, tắt service không đóng port, cmdlet in secret, escrow bị GPO chặn, `UsedSpaceOnly`, credential trong file tracked, v.v.
- **Cài đặt**: clone vào thư mục skill + copy command vào `~/.claude/commands/` để `/local-pc-security-audit` xuất hiện; kèm bản PowerShell và `--depth 1`.

### Ghi chú

- Read-only mặc định; không có payload/exploit.
- Chưa cấp license — dùng nội bộ, liên hệ tác giả trước khi tái phân phối.

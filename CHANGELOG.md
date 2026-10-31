# Changelog

Mọi thay đổi đáng chú ý của skill này được ghi ở đây.
Định dạng theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/); phiên bản theo [SemVer](https://semver.org/lang/vi/).

## [1.3.0] — 2026-10-31

### Thêm & Nâng cấp

- **Tự động kiểm tra bản cập nhật Skill từ GitHub**: Tích hợp Bước 0 kiểm tra version mới nhất trên remote repository trước mỗi phiên audit. Nếu có bản mới hơn, Agent sẽ dừng lại hỏi người dùng xác nhận cập nhật (`npx skills update` hoặc `git pull`).
- **Bộ Proactive Baseline Hardening tùy biến chuyên sâu cho từng OS**:
  - **Windows**: LSA Protection (RunAsPPL=2), Credential Guard, tắt broadcast LLMNR/NetBIOS, Defender ASR rules, UAC prompt strictness, dọn dẹp PATH.
  - **macOS**: Ép bật SIP & Gatekeeper, Application Firewall Stealth mode, huỷ key FileVault khỏi RAM khi sleep (`destroyfvkeyonstandby`), tắt Remote Login/VNC.
  - **Linux**: Hạn chế ptrace scope (`kernel.yama.ptrace_scope = 2`), cấm core dump, UFW Default Deny, cô lập Docker socket (không thêm user vào group `docker`).
- **Rà soát Shadow Browser Automation & Sandbox Escape**: Quét cache Chromium chạy ngầm của Playwright / Puppeteer (`ms-playwright`), kiểm tra cờ nguy hiểm `--no-sandbox` và rà soát quyền Accessibility (TCC / UI Automation) chống leo thang chiếm quyền điều khiển OS.
- **Quy trình Main Agent Elevated Re-run**: Bắt buộc Agent sau lượt audit non-elevated phải gom toàn bộ các mục bị chặn bởi `Access denied` để xin phép user chạy 1 lượt elevated duy nhất qua UAC / sudo nhằm khép kín báo cáo đo lường.

## [1.2.0] — 2026-10-31

### Thêm & Cải tiến

- **Bắt buộc Full CVE Report ngay lập tức (Immediate Full CVE Report)**: Cập nhật Phase 9 của `SKILL.md` và Bước 8 của `PROMPT.md` quy định cứng việc xuất bản bảng phân tích CVE lỗ hổng (OS, Browser, Remote-Access, High-Risk Apps) tích hợp đầy đủ ngay trong báo cáo audit chính, không tách rời hoặc chờ user yêu cầu.
- **Interactive Remediation Triage**: Chuẩn hoá mục hướng dẫn và prompt tương tác sau audit vào cấu trúc báo cáo bắt buộc và cả hai bản README (VI/EN), giúp Agent và người dùng lần lượt duyệt qua từng finding với các phương án Accept / Fix an toàn.

## [1.1.0] — 2026-10-31

### Thêm

- **Cài đặt Universal qua `npx skills add`**: Hỗ trợ 1-liner cài đặt tự động cho hơn 20 agent harnesses (`npx skills add duhd/local-workstation-security-audit -g -y`).
- **Quy định bắt buộc Scan CVE (Mandatory CVE Scanning)** trong nguyên tắc bất biến #9 của skill và các chế độ audit.
- **Hướng dẫn chi tiết đa nền tảng**: Bổ sung hướng dẫn cài đặt & tích hợp riêng cho Claude Code, Oh My Pi (omp), OpenAI Codex CLI, Cursor/Windsurf (MDC rules), và Claude Desktop (Terminal MCP).
- **Bổ sung pipeline Grype chuẩn**: Hoàn thiện hướng dẫn catalog package (SBOM-lite), match có version constraint, enrich qua EPSS/KEV và chính sách VEX có thời hạn.

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

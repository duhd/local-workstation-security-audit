# Changelog

Mọi thay đổi đáng chú ý của skill này được ghi ở đây.
Định dạng theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/); phiên bản theo [SemVer](https://semver.org/lang/vi/).

## [1.5.1] — 2026-11-01

### Sửa lỗi

- **Thứ tự thực thi còn sót ở 3 entry point**: v1.5.0 chỉ sửa `SKILL.md` + `PROMPT.md`; slash command `commands/local-pc-security-audit.md` và đoạn "Dành cho agent" trong `README.md` / `README.en.md` vẫn bảo chạy "Phase 1 → 9 rồi 10 → 17" và thiếu lượt elevated trước report. Cả 3 nay trỏ về mục *Thứ tự thực thi (full audit)*: thu thập 1–6 ∥ 10–17 → elevated → Phase 7 → Phase 9 report → Phase 8 triage.

## [1.5.0] — 2026-11-01

### Thay đổi

- **Thứ tự thực thi full audit được chuẩn hoá**: Bước 0 → thu thập (Phase 1–6 do parent chạy, song song Phase 10–17 theo slice A–D) → lượt elevated → Phase 7 → Phase 9 report → Phase 8 triage. Trước đây bảng chế độ ghi "Phase 1→9", Phase 10–17 "chạy sau Phase 9" (sau khi report đã chốt) và multi-subagent không giao Phase 1–6 cho ai ⇒ finding attacker-first có thể không vào report/triage. `PROMPT.md` áp cùng thứ tự; lượt elevated gộp về một chỗ (trước report).
- **Quy đổi severity**: Critical = P0 · High = P1 · Medium = P2 · Low = P3; Informational không vào triage.
- **Làm rõ luật gọi API ngoài**: cấm probe hạ tầng tổ chức/máy khác; được phép GET không kèm credential tới nguồn dữ liệu công khai skill chỉ định (GitHub `VERSION`, NVD, MSRC, EPSS, OSV, GHSA, chromiumdash).

### Sửa lỗi (lệnh sai — đã đối chiếu tài liệu Microsoft)

- **ASR**: thay 2 GUID không tồn tại bằng GUID thật (`d4f940ab-401b-4efc-aadc-ad5f3c50688a` Office child process, `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` LSASS); dùng `Add-MpPreference` thay `Set-MpPreference` (lệnh `Set-` ghi đè toàn bộ danh sách ASR); rollback bằng `Remove-MpPreference`.
- **UAC**: `ConsentPromptBehaviorAdmin` đổi `2` → `1` — `2` chỉ hỏi Yes/No, `1` mới bắt nhập credential.
- **RunAsPPL**: rollback không còn gợi ý đặt `1` (bật kèm UEFI lock); dùng xoá value hoặc `0` + reboot; ghi rõ cần reboot khi bật.
- **Disable account macOS**: thay `dscl . -delete` (xoá account, không hoàn tác được) bằng `pwpolicy -disableuser` / `-enableuser`.
- **Phase 6**: pipeline quét `.gitmodules` không còn treo khi không có file (grep chờ stdin) và không tách path có dấu cách (`find -print0 | xargs -0 -r`); tìm repo bỏ `-type d` để không sót worktree/submodule (`.git` là file).
- `apt list --upgradable | wc -l` đếm thừa dòng `Listing...` → `grep -c upgradable`.
- Phase 15: PSK Wi-Fi WPA2-Personal chỉ đọc được với quyền admin.

## [1.4.2] — 2026-11-01

### Sửa lỗi

- **Đồng bộ prompt mẫu ở Phase 9 với luật 2 nhánh của Phase 8**: prompt mẫu cuối report vẫn chỉ dẫn "sử dụng công cụ Ask Question", mâu thuẫn với việc v1.4.1 đã cho phép menu đánh số khi harness không có tool đó. Prompt mẫu nay ghi rõ: harness có `ask` / `AskUserQuestion` thì gọi tool, không có thì in menu đánh số và dừng chờ.

## [1.4.1] — 2026-11-01

### Sửa lỗi

- **Ask Question tool là điều kiện, không phải luật tuyệt đối**: v1.4.0 cấm "dump văn bản" và bắt buộc gọi `ask` / `AskUserQuestion`, nhưng skill được cài cho hơn 20 harness (`~/.agents/skills/`) — Codex CLI, Cursor, Windsurf, Cline, Claude Desktop không có tool này, khiến Agent rơi vào thế phải vi phạm luật. Phase 8 của `SKILL.md` và Bước 9 của `PROMPT.md` nay tách thành 2 nhánh: **A** gọi Ask Question tool khi harness có; **B** in menu đánh số `Accept / Fix tối thiểu / Fix triệt để` và dừng chờ user trả lời khi harness không có. Chạy non-interactive (CI/batch/cron) → dừng ở chế độ read-only report, không tự áp dụng remediation.

## [1.4.0] — 2026-11-01

### Thêm & Cải tiến

- **Bắt buộc dùng Ask Question tool cho Interactive Triage**: Phase 8 của `SKILL.md` và Bước 9 của `PROMPT.md` quy định Agent PHẢI gọi công cụ `ask` / `AskUserQuestion` để hỏi người dùng lựa chọn (Accept / Fix tối thiểu / Fix triệt để) theo giao diện trắc nghiệm tương tác, thay vì dump văn bản hoặc tự suy đoán. Mỗi option bắt buộc nêu lệnh sẽ chạy, hệ quả và rollback.
- **Cập nhật prompt mẫu trong cả hai bản README (VI/EN)** để hướng người dùng kích hoạt đúng cơ chế Ask Question khi yêu cầu Agent triage sau audit.

## [1.3.1] — 2026-10-31

### Sửa lỗi & Cải tiến

- **Chuẩn hoá lệnh cập nhật `npx skills update`**: Sửa lệnh trong tài liệu và prompt từ `npx skills update duhd/...` sang đúng tên định danh cài đặt `npx skills update local-workstation-security-audit -g -y`, khắc phục lỗi `No installed skills found matching` và crash assertion của Node libuv trên Windows.

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

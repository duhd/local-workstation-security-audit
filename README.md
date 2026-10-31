# Local Workstation Security Audit

Skill + prompt để audit bảo mật **máy trạm cá nhân** trên Windows, macOS và Linux.

> **Máy dev không phải endpoint. Nó là một đường vào production.**
>
> Máy của dev, devops, SRE hay staff thường mang theo: private key SSH không passphrase, `kubeconfig` của cluster thật, token CI/CD, PAT đọc repo nội bộ, credential cloud, và cả lịch sử lệnh có dán secret. Những thứ đó không cần lỗ hổng nào để bị dùng — chỉ cần một lần máy bị chiếm, một lần cài nhầm package, một lần clone repo lạ có `.gitmodules` chứa token, hoặc một lần mất máy không mã hoá ổ.
>
> Đây đúng là đường vào của các vụ lớn gần đây: kẻ tấn công không phá blockchain, không đánh vào smart contract — chúng lấy được máy của một người có quyền, rồi đi tiếp bằng chính credential hợp lệ. Vụ tấn công sàn Binance với thiệt hại được báo cáo lên tới hàng tỷ USD (≈6,63 tỷ USD theo các bản tin công khai — cần đối chiếu nguồn sơ cấp nếu dùng trong tài liệu chính thức) là ví dụ của cùng một mô thức: **một endpoint bị chiếm → credential hợp lệ → hệ thống live**.
>
> Vì vậy audit máy trạm không phải việc "dọn dẹp cho gọn". Nó là kiểm tra xem đường vào đó đang mở bao nhiêu.

## Repo này có gì

| File | Dùng để |
|---|---|
| `SKILL.md` | Skill đầy đủ: luật bằng chứng, bảng lệnh 3 OS theo từng phase, neo mức độ, playbook remediation, bảng bẫy đã cắn thật, và **phạm vi attacker-first** (Phase 10–17) |
| `PROMPT.md` | Prompt dán thẳng vào agent bất kỳ, không cần skill loader |
| `commands/local-pc-security-audit.md` | Entry point dạng slash command cho harness đọc thư mục `commands/` |

## Cách dùng

**Có skill loader**: copy `SKILL.md` vào thư mục skill của harness (dạng `skills/local-workstation-security-audit/SKILL.md`), rồi gọi lệnh:

```
/local-pc-security-audit
```

**Không có skill loader**: dán nội dung `PROMPT.md` vào agent. Điều kiện bắt buộc: agent phải có tool shell. Nếu không, nó phải dừng và yêu cầu bạn dán output — không được mô tả lại checklist như thể đã kiểm.

## Phạm vi

**Phase 1–9 (posture):** patch OS · mã hoá ổ · TPM/Secure Boot/SIP · firewall + listener + ACL mạng overlay · credential at-rest (git, ssh, cloud, agent home) · persistence (autorun/launchd/systemd/task/service) · browser profile + extension + remote-access host · repo & lịch sử git · patch gap ứng dụng · severity · remediation · report.

**Phase 10–17 (attacker-first — phần thường bị bỏ sót):**

| Phase | Câu hỏi |
|---|---|
| 10 | Ai còn đăng nhập được máy này? (`authorized_keys`, Credential Manager/Keychain, shell history, `AutoAdminLogon`, LSA protection) |
| 11 | Kẻ tấn công có thể chạy code của mình bằng cách nào? (PATH hijack, service path, service DACL, `SeImpersonate`, `AlwaysInstallElevated`, git hooks, registry package manager, WSL/docker, extension `update_url`) |
| 12 | Secret còn nằm ở đâu sau khi "đã xoá"? (tfstate, crash dump, editor backup, notebook output, Postman, Recycle Bin, shadow copy, `git fsck`) |
| 13 | Kênh tin cậy có bị chiếm không? (root CA lạ, updater, `winget source`) |
| 14 | Còn phát hiện được gì? (audit policy, PowerShell 4104, Sysmon/AMSI, log retention, forwarder thật sự nhận log) |
| 15 | Có kênh nào ngoài listener? (Wi-Fi PSK, LLMNR/NetBIOS, file `.lnk/.scf` trong repo gây lộ NTLM hash, spooler/WebDAV) |
| 16 | Chạm được máy thì sao? (auto-login, khoá màn hình, boot order, BIOS password, hibernation) |
| 17 | Bề mặt AI agent (`.mcp.json` `command`, hook agent, `approvalMode`, transcript, daemon loopback) |

## Nguyên tắc cốt lõi

- **Read-only mặc định.** Chỉ thay đổi hệ thống khi bạn chọn phương án cho từng finding.
- **Không in secret.** Chỉ ghi tên biến, độ dài, đường dẫn. Lệnh nào có thể in value (`git remote -v`, `git config --get-regexp 'remote.*'`, `manage-bde -status`) phải redact ngay trong pipeline.
- **Mỗi phép đo phải có positive control.** Filter hẹp tạo false negative: "không tìm thấy" thường là "tìm sai cách", không phải "không tồn tại".
- **Ba trạng thái, không hai.** *Đã kiểm và sạch* / *đã kiểm và có vấn đề* / **chưa kiểm được** — trạng thái thứ ba không được gộp vào "sạch". `Access denied` thuộc loại thứ ba.
- **Verify bằng trạng thái, không bằng exit code**, và **đo lại sau khi sửa** (tắt service có thể không đóng port; deny ACL chỉ áp handle mới; provisioner có thể tạo lại account; `UsedSpaceOnly` báo 100% mà free space vẫn plaintext).
- **Thứ tự remediation**: revoke credential → siết quyền/ACL → rewrite lịch sử/tắt service.

## Output

Report `docs/security/<YYYY-MM-DD>-local-workstation-security-audit.md`:

1. Metadata (host, OS, quyền, phạm vi)
2. Bảng finding xếp theo **blast radius**, kèm *tác động quan sát được*
3. Mỗi finding đủ 4 phần: **Evidence / Fix / Verify / Rollback**
4. Trạng thái khắc phục: đã áp dụng · đã thử và rollback · còn chờ
5. Kết luận đã bị bác bỏ (để người sau không lặp lại)
6. Giới hạn coverage (mục nào chưa kiểm và vì sao)

Report chứa IP, hostname, đường dẫn nội bộ ⇒ coi là tài liệu nội bộ, đừng commit vào repo công khai.

## Giới hạn & đạo đức

Repo này **chỉ mô tả bề mặt và cách kiểm read-only**. Không có payload, không có exploit, không có PoC leo thang đặc quyền. Đừng chạy thử tấn công trên máy thật; nếu cần chứng minh một đường leo thang, làm trên VM cô lập.

Và: một danh sách phạm vi **không** thay thế phép đo. Mục chưa kiểm phải ghi "chưa kiểm", không bao giờ ghi "không có".

## Ghi chú

Skill này được đúc kết từ một phiên audit thật, trong đó nhiều kết luận ban đầu phải sửa lại vì false negative (filter hẹp, `ls -la` trên Windows, output bị redact, tắt service không đóng port…). Bảng "Bẫy đã cắn thật" trong `SKILL.md` là phần giá trị nhất — đọc trước khi chạy.

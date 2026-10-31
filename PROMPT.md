# Prompt — audit bảo mật máy trạm (dán vào agent bất kỳ, Windows/macOS/Linux)

> Yêu cầu trước khi chạy: agent **phải có tool shell** (Bash/PowerShell/terminal). Nếu không có shell, dừng lại và yêu cầu tôi dán output của các lệnh — tuyệt đối không mô tả lại checklist như thể đã kiểm.
> Nếu agent đọc được skill `local-workstation-security-audit` thì đọc SKILL.md trước (bảng lệnh 3 OS nằm ở Phase 1–4) và bỏ qua phần trùng.

---

## Prompt

Bạn là kỹ sư bảo mật đang audit **máy trạm mà bạn đang chạy trên đó** (Windows / macOS / Linux). Read-only mặc định: chỉ thay đổi hệ thống khi tôi chọn phương án cho từng finding.

**Luật cứng:**

1. Không in giá trị secret. Chỉ ghi *tên biến + độ dài + đường dẫn*. Lệnh nào có thể in value (`git remote -v`, `git config --get-regexp 'remote.*'`, `manage-bde -status`) phải redact ngay trong pipeline (`| sed -E 's#://[^@/]+@#://<redacted>@#'`).
2. Không kết luận "không có / không mở" từ phép đo hẹp. Mỗi phép tìm phải kèm **positive control**; control = 0 kết quả ⇒ kênh đo hỏng, không phải hệ thống sạch.
3. Phân biệt rõ: *đã kiểm và sạch* / *đã kiểm và có vấn đề* / **chưa kiểm được (nêu lý do)**. `Access denied` thuộc loại thứ ba, không phải "không tồn tại".
4. Verify bằng **trạng thái** (query lại port/service/ACL/encryption status), không bằng exit code.
5. Mọi thay đổi có rollback; thao tác không hoàn tác được phải hỏi tôi trước.
6. Không probe hệ thống ngoài máy; không dùng thử credential thu được bằng cách gọi API thật.

**Bước 0 — Bối cảnh.** In hostname, OS + version, user, có admin/root không, shell đang dùng. Thiếu quyền admin thì chạy hết phần không cần admin trước, phần còn lại để lượt elevated.

**Bước 1 — Posture.** Patch OS (dùng update searcher của OS, không dùng danh sách KB), mã hoá ổ, TPM/Secure Boot/SIP, firewall + default inbound action, UAC/sudo, AV/EDR đang chạy.
Lệnh theo OS: `manage-bde -status` / `fdesetup status` / `lsblk`+`cryptsetup status`; `Get-Tpm`+`Confirm-SecureBootUEFI` / `csrutil status` / `mokutil --sb-state`; `Get-NetFirewallProfile` / `socketfilterfw --getglobalstate`+`pfctl -s rules` / `ufw status`+`nft list ruleset`.
**Và patch gap của ứng dụng — đừng nhầm với patch OS:** `winget upgrade --include-unknown` / `brew outdated --greedy` / `apt list --upgradable`; lấy version browser đang cài (`chrome.exe` VersionInfo / `defaults read` / `google-chrome --version`) so với latest stable (Chrome: `chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows|Mac|Linux&num=1` — đã verify 3 giá trị này, `Win` trả rỗng; Edge: `winget show Microsoft.Edge`; Safari: theo OS); liệt kê remote-access host (Chrome Remote Desktop `chromoting`, AnyDesk, RustDesk) — lệch **major** version trong khi service đang chạy là finding ưu tiên cao. Ghi rõ **patch gap ≠ CVE mapping**: nếu chưa đối chiếu NVD/MSRC thì kết luận là "lệch bản mới nhất, mức khai thác chưa xác định", không viết như vulnerability scan. Nếu nguồn "latest" trả rỗng/không parse được thì ghi "chưa xác định", không suy ra "đã cập nhật".

**CVE mapping — chỉ cho nhóm rủi ro cao** (browser, remote-access host, OS component, VPN client, trình đọc/giải nén file), không map toàn bộ app đã cài. Làm theo pipeline kiểu Grype: **(1) catalog** package (`winget list` / `dpkg-query -W` / `brew list --versions` / `npm ls -g --json` / `pip list --format=json`) → **(2) match** theo ecosystem (distro dùng USN/DSA/RHSA; app third-party dùng NVD `cpeName` với **version đang cài** hoặc `keywordSearch`; Windows/Edge dùng MSRC; npm/pip/go dùng OSV `POST /v1/query` hoặc GHSA) → **(3) enrich** bằng EPSS (`api.first.org/data/v1/epss?cve=…`) và KEV (nếu bị chặn thì ghi "chưa truy vấn được") → **(4) policy** `.audit-vex.yaml` có `reason` + `expires` → **(5) output** tái lập kèm timestamp và `fix.state` (`fixed|wont-fix|unknown`). Gate: flag khi `fix.state=fixed` và (`KEV` hoặc `EPSS≥0.1` hoặc `CVSS≥7`). Nguồn GET-only: NVD (`services.nvd.nist.gov/rest/json/cves/2.0`, rate 5 req/30s khi không có key), MSRC (`api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability`). Report phải ghi `CVE-id` + CVSS + `fixed version` + nguồn + ngày truy vấn. **Positive control bắt buộc**: `?keywordSearch=chrome` phải trả >0 kết quả; nếu 0/404 thì ghi "chưa truy vấn được", không kết luận "không có CVE". `cpeName` chỉ nhận version cụ thể (wildcard `*` → 404). Không chạy PoC, không gửi credential khi gọi API ngoài.

**Bước 2 — Bí mật trên đĩa.** Vị trí + quyền của: git credential (file, helper, credential nhúng trong URL), cloud/registry config, kubeconfig, SSH key (**kiểm passphrase bằng `ssh-keygen -y -P "" -f`**), dotfile agent/harness, credential store của OS (`security find-generic-password` / `secret-tool`). Quyền: `icacls` / `namei -l`+`stat` / `getfacl` — **không** dùng `ls -la` khi chạy trên Windows qua MSYS.

**Bước 3 — Exposure mạng.** Listener (bind `127.0.0.1` vs `0.0.0.0`/`::`, process sở hữu), rule inbound **enabled** (luôn kiểm cột enabled; luôn có nhánh rule `Port=Any`), VPN/mesh (đọc cả ACL control plane), chia sẻ file/remote, container/VM port publish. Kết luận phải nêu **cả hai lớp**: firewall host và lớp mạng.

**Bước 4 — Persistence.** Autorun/launchd/systemd/cron/task/service: resolve target + chữ ký, kiểm quyền thư mục chứa (path user-writable + chạy quyền cao = điểm persistence thật), phân biệt binary với COM handler.

**Bước 5 — Browser.** Profile + kích thước `Login Data`/`Cookies` + extension (map tên thật), remote-desktop host, PWA tự chạy khi login. Không giải mã credential browser.

**Bước 6 — Repo.** Tìm mọi `.git`, quét config cấp repo + `.gitmodules` (chỉ `grep -l`, không `-o/-h`). Credential trong file **tracked** → xác định `HEAD:<file>`, commit nào đưa vào (`git log -S`), đã push nhánh nào (`git branch -r --contains`) rồi mới kết luận mức.

**Bước 7 — Lượt elevated.** Gom vào **một** script: BitLocker/FileVault/LUKS status, TPM/Secure Boot, Defender exclusion + preference, EDR service state, log location. Ghi transcript ra temp, verify bằng state, xoá script/log sau (nếu log từng chứa secret → coi như đã lộ, rotate lại).

**Bước 8 — Report (Bắt buộc Full ngay lập tức, không để chờ hỏi).** Ghi `docs/security/<YYYY-MM-DD>-local-workstation-security-audit.md` tích hợp đầy đủ trong một báo cáo duy nhất:
1. Metadata (host, OS, quyền, phạm vi).
2. Bảng finding xếp theo blast radius (P0→P3).
3. **Báo cáo Lỗ hổng & CVE (bắt buộc)**: Bảng định danh CVE chi tiết cho OS, trình duyệt (Chrome/Edge), Remote-Access host (CRD, AnyDesk), phần mềm rủi ro cao (Git, 7-Zip), đối chiếu NVD/MSRC, kèm chỉ số EPSS và CISA KEV.
4. Chi tiết từng finding đủ **Evidence / Fix / Verify / Rollback**.
5. Trạng thái khắc phục (đã áp dụng · đã thử và rollback · còn chờ).
6. Kết luận đã bị bác bỏ và Giới hạn coverage.
7. **Mục cuối cùng bắt buộc đính kèm đoạn prompt mẫu "Hướng dẫn tiếp theo: Chạy Interactive Remediation Triage"** để user có thể dán tiếp cho phiên sau.
Report chứa topology/IP/path nội bộ ⇒ coi là tài liệu nội bộ, không push remote công khai. Trước khi bàn giao grep report cho `sk-`, `ghp_`, `ya29.`, `-----BEGIN`, `\d{6}(-\d{6}){7}`, `://[^/]+:[^/]+@` và redact.

**Bước 9 — Hỏi tôi từng finding & Đề xuất Hardening.**
- Với từng finding: 3–4 phương án (Accept / Fix tối thiểu / Fix + rotate / Fix toàn bộ), mỗi phương án ghi lệnh, hệ quả, khả năng phá chức năng, rollback. Chỉ thực thi sau khi tôi chọn.
- **Đề xuất Hardening chủ động (Customized theo đúng OS máy trạm)**: Ngoài sửa lỗi, hãy căn cứ vào OS của máy (Windows/macOS/Linux) để gợi ý bộ thiết lập phòng ngừa theo bảng *Proactive Baseline Hardening* trong `SKILL.md` (RunAsPPL/ASR trên Windows; SIP/destroyfvkeyonstandby trên macOS; ptrace_scope/UFW/Docker socket isolation trên Linux).
Thứ tự khi có nhiều lớp: **(1) revoke credential → (2) siết quyền/ACL → (3) rewrite lịch sử / tắt service**.
Sau mỗi thay đổi, **đo lại bằng đúng phép đo đã dùng để phát hiện** và ghi trước/sau — vì: tắt service có thể không đóng port (kernel giữ); deny ACL chỉ áp handle mới (phải restart process); provisioner service có thể tạo lại account đã disable; `UsedSpaceOnly` báo 100% nhưng free space vẫn plaintext.

**Bẫy phải tránh (đã cắn thật):** filter hẹp ⇒ false negative · `Get-NetFirewallRule` trả cả rule disabled · `ls -la` trên Windows qua MSYS báo sai ACL · output bị tool redact làm tưởng file chứa `[REDACTED]` · tắt service không đóng port · "không có event log" ≠ "không có telemetry" (Splunk/Wazuh/ManageEngine) · service provisioner bật lại account · cmdlet BitLocker mỗi lần chỉ nhận một protector và **in recovery password ra console** · escrow có thể bị GPO chặn · `-UsedSpaceOnly` để free space plaintext · DENY thắng inherited nhưng chủ sở hữu vẫn đọc được · credential trong file **tracked** thì sửa working tree là không đủ · `git config --get-regexp 'remote.*'` in token.

Bắt đầu bằng Bước 0, chạy tuần tự, không bỏ bước nào. Mục không kiểm được → ghi vào *giới hạn coverage*, không suy đoán.

**Bước bổ sung — phạm vi attacker-first (Phase 10–17), chạy sau Bước 8, trước khi chốt report.** Bước 1–8 phủ cấu hình nhìn thấy được; phần dưới là thứ kẻ tấn công thật sự dùng và thường bị bỏ sót. Checklist chi tiết + lệnh 3 OS nằm ở mục *Phạm vi bổ sung — attacker-first (Phase 10–17)* trong `SKILL.md`:

**Nếu có tool subagent: chạy 4 slice song song như mục *Chạy multi-subagent* trong `SKILL.md` — A (17+10), B (12), C (11+13), D (14+15+16).** Mỗi prompt con phải copy đủ 7 điều trong hợp đồng (read-only · không in secret · positive control · 3 trạng thái · Access denied ⇒ chưa kiểm · không PoC · output 4 mục). Agent chỉ đề xuất mức; bạn là người duy nhất ghi report, dedupe, và quyết severity theo Phase 7. Không có subagent thì chạy tuần tự 17 → 10 → 12 → 11 → 14 → 13 → 15 → 16 và ghi rõ là đơn luồng.


1. **Danh tính**: ai còn trong `authorized_keys`; Credential Manager/Keychain/`secret-tool`; shell history (grep pattern token, không in giá trị); `AutoAdminLogon` + `DefaultPassword` (cleartext); LSA protection / Credential Guard / ptrace_scope; cached logons.
2. **Thực thi code & leo thang**: thư mục trong `PATH` mà user ghi được; service path không quote + binary ghi được; service DACL; `whoami /priv`; `AlwaysInstallElevated`; git hook/`include.path`/`insteadOf`/`credential.helper` lạ; registry npm/pip/nuget; WSL `docker.sock` + `--privileged` + sudoers; extension `update_url`/native messaging; `.vscode/tasks.json` `runOn`.
3. **Secret trong artifact**: `*.tfstate`/`*.tfplan`/`terraform.tfvars`; crash dump (`%LOCALAPPDATA%\CrashDumps`); editor swap/backup + JetBrains `LocalHistory`; notebook outputs; Postman/Insomnia/`.har`; Recycle Bin; `vssadmin list shadows`; `git fsck --lost-found` + `git stash`; **thư mục đang sync OneDrive/Drive**; `pagefile.sys`/`hiberfil.sys`.
4. **Kênh tin cậy**: root CA lạ trong machine store; trạng thái + quyền ghi của updater; `winget source list`; AppLocker/WDAC/SELinux/AppArmor.
5. **Năng lực phát hiện**: audit policy (4688 + command line, 5140/5145, 4663); PowerShell ScriptBlock/Transcription; Sysmon/AMSI/ETW; log size + event 1102; forwarder có thật sự nhận log.
6. **Mạng ngoài listener**: `netsh wlan show profiles` (chỉ tên + auth type; profile `WPA2-Personal` nghĩa là PSK đọc được — chỉ ghi nhận, **không** trích xuất); LLMNR/NetBIOS/mDNS; file `.lnk/.url/.scf` trong repo (NTLM leak); Print Spooler/WebClient/`Search-ms`; proxy/PAC/DoH/split tunnel.
7. **Vật lý/pre-boot**: khoá màn hình + yêu cầu mật khẩu khi wake; boot order/USB boot; BIOS password; hibernation + Fast Startup; escrow recovery key.
8. **AI agent surface**: mọi `command` trong `.mcp.json` (chạy binary gì, đường dẫn có ghi được); hook agent (`PreToolUse`…); `approvalMode`/allow-list; transcript + agent DB (secret user dán vào); daemon loopback không auth (CDP, orchestrator); autostart của agent.

Mỗi mục: nếu **chưa đo** thì ghi "chưa kiểm", tuyệt đối không ghi "không có".

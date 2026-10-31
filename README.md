# Local Workstation Security Audit

**Máy bạn đang giữ chìa khoá vào production. Mất 60 giây để biết nó đang mở bao nhiêu.**

Không phải lý thuyết. Trên một máy dev bình thường có thể đồng thời tồn tại: private key SSH không passphrase, `kubeconfig` của cluster thật, token CI/CD, PAT đọc repo nội bộ, credential cloud, ổ đĩa chưa mã hoá, và ba browser profile đang đăng nhập. Không cần lỗ hổng nào để những thứ đó bị dùng — chỉ cần **một** trong các chuyện sau:

- bạn clone một repo lạ, và `.gitmodules` của nó chứa token;
- bạn cài một package, và `postinstall` của nó đọc `~/.ssh`;
- bạn mất máy, hoặc ai đó boot bằng USB;
- một agent AI chạy lệnh trong repo đó mà không cần phê duyệt.

Các vụ mất tiền mã hoá quy mô lớn gần đây đều đi đúng con đường này: **một endpoint bị chiếm → credential hợp lệ trên máy đó → hệ thống live**. Vụ LastPass 2022 là ví dụ gọn nhất và kiểm chứng được: kẻ tấn công vào máy cá nhân của một kỹ sư DevOps, rồi lấy được vault.

Repo này là checklist thực thi cho bước "kiểm tra endpoint" đó — chạy trên Windows, macOS và Linux.

---

## Cài trong 60 giây

**Cách nhanh nhất (khuyên dùng — tự động nhận diện mọi CLI/Agent):**
```bash
npx skills add duhd/local-workstation-security-audit -g -y
```
*Lệnh trên tự động cài đặt skill vào thư mục chuẩn `~/.agents/skills/` và tạo symlink cho Claude Code, Codex, Amp, Antigravity, Cline, OpenCode, v.v.*

---

Hoặc chọn cách cài thủ công theo từng công cụ dưới đây:

### 1. Claude Code

**macOS / Linux / Git Bash:**
```bash
mkdir -p "$HOME/.claude/skills" "$HOME/.claude/commands"
git clone --depth 1 https://github.com/duhd/local-workstation-security-audit \
  "$HOME/.claude/skills/local-workstation-security-audit"
cp "$HOME/.claude/skills/local-workstation-security-audit/commands/local-pc-security-audit.md" "$HOME/.claude/commands/"
/local-pc-security-audit
```

**Windows PowerShell:**
```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.claude\skills","$env:USERPROFILE\.claude\commands" | Out-Null
git clone https://github.com/duhd/local-workstation-security-audit "$env:USERPROFILE\.claude\skills\local-workstation-security-audit"
Copy-Item "$env:USERPROFILE\.claude\skills\local-workstation-security-audit\commands\local-pc-security-audit.md" "$env:USERPROFILE\.claude\commands\"
```

### 2. Oh My Pi (omp) / Pi CLI

`omp` và `pi` tự động nhận diện skill đặt trong thư mục agent home:
```bash
# Windows PowerShell:
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.omp\agent\skills" | Out-Null
git clone https://github.com/duhd/local-workstation-security-audit "$env:USERPROFILE\.omp\agent\skills\local-workstation-security-audit"

# macOS / Linux:
mkdir -p "$HOME/.omp/agent/skills"
git clone https://github.com/duhd/local-workstation-security-audit "$HOME/.omp/agent/skills/local-workstation-security-audit"
```
Khởi động lại session hoặc gõ `/skill:local-workstation-security-audit`.

### 3. OpenAI Codex CLI

Codex hỗ trợ load hướng dẫn agent qua prompt hoặc plugin:
```bash
# Cách nhanh nhất: Clone về thư mục tài liệu hoặc nạp qua system instructions
git clone --depth 1 https://github.com/duhd/local-workstation-security-audit "$HOME/.codex/skills/local-workstation-security-audit"
```
Hoặc mở phiên Codex và chỉ định:
```bash
codex "Thực hiện audit bảo mật máy theo hướng dẫn trong ~/.codex/skills/local-workstation-security-audit/SKILL.md"
```

### 4. Cursor / Windsurf / VS Code (Agent Mode)

Đặt rule vào project hoặc thư mục làm việc hiện tại:
```bash
mkdir -p .cursor/rules   # Với Cursor
# Copy nội dung SKILL.md hoặc PROMPT.md vào:
cp "$HOME/.claude/skills/local-workstation-security-audit/SKILL.md" .cursor/rules/security-audit.mdc
```
Trong thanh chat của Cursor/Windsurf (Agent Mode): gõ `@security-audit.mdc chạy audit bảo mật cho máy này`.

### 5. Claude Desktop (GUI)

Claude Desktop không có shell mặc định. Hai cách dùng:
1. **Tự động (Khuyên dùng)**: Thêm 1 Terminal MCP Server (như `@wonderwhy-er/desktop-commander` hoặc MCP shell bất kỳ) vào `%APPDATA%\Claude\claude_desktop_config.json`. Sau đó dán `PROMPT.md` vào chat để Claude tự chạy lệnh.
2. **Bán tự động (Human-in-the-loop)**: Dán trực tiếp `PROMPT.md` vào chat. Claude sẽ soạn từng block lệnh cho bạn copy vào PowerShell/Terminal chạy, rồi bạn dán kết quả ngược lại để Claude phân tích.

### 6. Mọi công cụ AI Agent khác (Generic)

Mở file [`PROMPT.md`](PROMPT.md), copy toàn bộ nội dung và dán vào cửa sổ chat của bất kỳ Agent nào có quyền thực thi shell.

Điều kiện để chạy audit: agent phải có tool shell (Bash / PowerShell / terminal). Không có shell thì nó phải dừng và yêu cầu bạn dán output — **không** được mô tả lại checklist như thể đã kiểm.

**Tự động kiểm tra bản mới**: Skill và Prompt đã tích hợp sẵn bước kiểm tra phiên bản mới nhất trên GitHub ở đầu mỗi lần chạy. Nếu phát hiện bản mới, Agent sẽ tự động hỏi ý kiến bạn trước khi tiến hành cập nhật.

**Cập nhật thủ công lên bản mới**:
- **Nếu cài qua `npx skills`**:
  ```bash
  # Dùng tên skill đã cài đặt (local-workstation-security-audit):
  npx skills update local-workstation-security-audit -g -y
  ```
- **Nếu cài qua `git clone`**:

```bash
git -C "$HOME/.claude/skills/local-workstation-security-audit" pull --ff-only
# command là BẢN COPY, không phải symlink — phải copy lại sau mỗi lần pull
cp "$HOME/.claude/skills/local-workstation-security-audit/commands/local-pc-security-audit.md" \
   "$HOME/.claude/commands/"
```

Ở Windows PowerShell:

```powershell
git -C "$env:USERPROFILE\.claude\skills\local-workstation-security-audit" pull --ff-only
Copy-Item "$env:USERPROFILE\.claude\skills\local-workstation-security-audit\commands\local-pc-security-audit.md" `
  "$env:USERPROFILE\.claude\commands\" -Force
```

Sau khi copy, khởi động lại harness (hoặc reload skills) để lệnh xuất hiện.

> **Dành cho agent đang đọc file này:** bước tiếp theo là mở `SKILL.md`, chạy Phase 1 → 9 (posture) rồi Phase 10 → 17 (attacker-first). Một lượt đầy đủ là **cả 17 phase**; không có chuyện chỉ chạy một nửa. Nếu chỉ có ~30 phút thì chạy trước **Phase 1 (patch/mã hoá ổ), 3 (exposure mạng), 5 (browser)**, rồi **17 → 10 → 12** — đó là nhóm cho finding nặng nhất trên máy dev. Read-only mặc định. Không in secret. Trước khi thay đổi bất kỳ thứ gì trên máy, hỏi user chọn phương án cho từng finding.

---

## Repo có gì

| File | Vai trò |
|---|---|
| `README.md` | Bản giới thiệu tiếng Việt (file này) |
| `README.en.md` | Bản giới thiệu tiếng Anh |
| `SKILL.md` | Skill đầy đủ — luật bằng chứng, bảng lệnh 3 OS, neo mức độ, playbook remediation, bảng bẫy đã cắn thật, và **Phase 10–17** (attacker-first) |
| `PROMPT.md` | Prompt dán thẳng vào agent, không cần skill loader |
| `commands/local-pc-security-audit.md` | Entry point dạng slash command |
| `.gitattributes` | Chuẩn hoá LF để dùng được trên macOS/Linux |

---

## Nó kiểm cái gì

**Phase 1–9 — posture.** Patch OS (bằng update searcher, không bằng danh sách KB) · mã hoá ổ · TPM/Secure Boot/SIP · firewall + listener + ACL mạng overlay · credential at-rest · persistence · browser profile + extension + remote-access host · repo & lịch sử git · **patch gap ứng dụng + CVE mapping** (NVD/MSRC, chỉ nhóm rủi ro cao: browser, remote-access host, OS component, VPN, trình đọc file) · severity · remediation · report.

**Phase 10–17 — attacker-first.** Phần thường bị bỏ sót, vì nó không nằm trong checklist CIS nào. Bốn câu hỏi nó trả lời:

- **Ai còn đăng nhập được máy này?** — `authorized_keys`, Credential Manager/Keychain, shell history, `AutoAdminLogon`, LSA protection.
- **Chạy code của kẻ khác bằng cách nào?** — PATH hijack, service path/DACL, `SeImpersonate`, git hooks, registry package manager, WSL/docker, extension `update_url`.
- **Secret còn ở đâu sau khi "đã xoá"?** — tfstate, crash dump, editor backup, notebook output, shadow copy, `git fsck`, và thư mục đang sync cloud.
- **Còn phát hiện được gì, và kênh nào ngoài listener?** — audit policy, PowerShell 4104, Sysmon/AMSI, forwarder health; Wi-Fi PSK, LLMNR/NetBIOS, `.lnk/.scf` trong repo, spooler/WebDAV.

Danh sách đầy đủ 8 phase kèm lệnh cho cả 3 OS nằm trong mục *Phạm vi bổ sung — attacker-first* của [`SKILL.md`](SKILL.md) — đó là bản duy nhất cần cập nhật khi thêm phase mới.

### Hardening chủ động (Customized theo OS)

Không chỉ dừng lại ở việc phát hiện và vá lỗ hổng (Reactive), skill cung cấp bộ cấu hình **Hardening Baseline chủ động** thiết kế riêng cho từng hệ điều hành:
- **Windows**: LSA RunAsPPL chống Mimikatz LSASS, Credential Guard, tắt LLMNR/NetBIOS broadcast, tắt Fast Startup dump RAM, Defender ASR rules, UAC Strictness (Credentials prompt), sắp xếp lại PATH.
- **macOS**: Ép bật SIP & Gatekeeper, Application Firewall Stealth mode, huỷ key FileVault khỏi RAM khi sleep (`destroyfvkeyonstandby`), tắt Remote Login/VNC, giới hạn timeout sudo.
- **Linux**: Giới hạn ptrace scope (`kernel.yama.ptrace_scope = 2`), cấm core dump (`limits.conf`), UFW Default Deny, cô lập Docker socket (không đưa user vào group `docker`), SSH daemon hardening.
- **AI Agent & Dev Tooling**: Pin version MCP server, cấm auto-accept trên repo lạ, cách ly vault/token không lưu biến môi trường cố định.
---

## Năm nguyên tắc khiến report này khác một checklist

1. **Read-only mặc định.** Không thay đổi gì trên máy cho tới khi bạn chọn phương án cho từng finding.
2. **Không in secret.** Chỉ tên biến, độ dài, đường dẫn. Lệnh nào có thể in value (`git remote -v`, `git config --get-regexp 'remote.*'`, `manage-bde -status`) phải redact ngay trong pipeline.
3. **Mỗi phép đo có positive control.** "Không tìm thấy" thường là "tìm sai cách", không phải "không tồn tại" — filter hẹp tạo false negative, và false negative trong bảo mật tệ hơn không biết.
4. **Ba trạng thái, không hai.** *Đã kiểm và sạch* / *đã kiểm và có vấn đề* / **chưa kiểm được**. `Access denied` thuộc loại thứ ba.
5. **Verify bằng trạng thái, không bằng exit code** — và **đo lại sau khi sửa**: tắt service có thể không đóng port; deny ACL chỉ áp handle mở sau đó; provisioner có thể tạo lại account; `UsedSpaceOnly` báo 100% trong khi free space vẫn plaintext.

Thứ tự remediation khi có nhiều lớp: **revoke credential → siết quyền/ACL → rewrite lịch sử / tắt service**. Làm ngược lại (sửa file trước, quên revoke) là lỗi phổ biến nhất.

---

## Output

Report `docs/security/<YYYY-MM-DD>-local-workstation-security-audit.md`:

1. Metadata — host, OS, quyền, phạm vi.
2. Bảng finding **xếp theo blast radius** (P0 → P3), kèm *tác động quan sát được*.
3. Mỗi finding đủ 4 phần: **Evidence / Fix / Verify / Rollback**.
4. Trạng thái khắc phục: đã áp dụng · đã thử và rollback · còn chờ.
5. Kết luận đã bị bác bỏ — để lần sau không lặp lại.
6. Giới hạn coverage — mục nào chưa kiểm và vì sao.

Report chứa IP, hostname, đường dẫn nội bộ ⇒ **coi là tài liệu nội bộ**, đừng commit vào repo công khai.

### Tương tác sau Audit (Interactive Triage Prompt)

Sau khi hoàn tất audit và xuất report, **không nên tự ý sửa thủ công hay để Agent tự động sửa toàn bộ**. Bạn hãy dùng prompt mẫu sau để yêu cầu Agent phân tích và hỏi bạn từng finding:

```markdown
"Dựa trên báo cáo audit vừa hoàn thành, hãy đóng vai trò chuyên gia an ninh hệ thống và lần lượt hỏi tôi về từng finding (từ P0, P1 đến P3). Với mỗi finding, hãy cung cấp rõ:
1. Phương án Accept (chấp nhận rủi ro, phân tích hệ quả).
2. Các phương án Fix cụ thể (tối thiểu, triệt để, kèm lệnh sẽ chạy, kiểm tra tác động phá chức năng nếu có).
Chỉ thực thi phương án khi tôi đã đưa ra quyết định lựa chọn."
```

---

## Giới hạn & đạo đức

Repo này chỉ mô tả **bề mặt và cách kiểm read-only**. Không payload, không exploit, không PoC leo thang đặc quyền. Nếu cần chứng minh một đường leo thang, làm trên VM cô lập — không chạy thử trên máy thật.

Và một điều luôn đúng: **một danh sách phạm vi không thay thế phép đo.** Mục chưa kiểm phải ghi "chưa kiểm", không bao giờ ghi "không có".

---

## Phiên bản & phát hành

- Version hiện tại: xem file [`VERSION`](VERSION) — dạng SemVer.
- Lịch sử thay đổi: [`CHANGELOG.md`](CHANGELOG.md).
- Mỗi bản phát hành là một git tag `vX.Y.Z` + GitHub Release cùng nội dung changelog.

Quy trình phát hành (thủ công, không cần CI):

```bash
# 1) sửa nội dung, cập nhật CHANGELOG.md + VERSION
git commit -am "feat: <mô tả>"
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main --tags
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file CHANGELOG.md
```

## License

Chưa cấp license. Nội dung dùng nội bộ; muốn dùng lại hoặc phân phối, liên hệ tác giả. Nếu bạn muốn mở hoàn toàn, thêm file `LICENSE` (MIT/Apache-2.0/CC-BY-4.0) — quyết định đó thuộc về chủ repo.

## Ghi chú

Skill này được đúc kết từ một phiên audit thật, trong đó nhiều kết luận ban đầu phải sửa lại vì false negative: filter hẹp bỏ sót rule `Port=Any`, `ls -la` trên Windows báo sai ACL, output bị tool redact làm mất bằng chứng, tắt service không đóng port vì driver giữ socket, `Enable-BitLocker` in recovery password ra console. Bảng **"Bẫy đã cắn thật"** trong `SKILL.md` là phần giá trị nhất — đọc trước khi chạy.

Bản tiếng Anh: [`README.en.md`](README.en.md)

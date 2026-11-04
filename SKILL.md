---
name: local-workstation-security-audit
description: Use when auditing a personal workstation (Windows/macOS/Linux) for security posture and CVE vulnerabilities — disk encryption, credential at rest, network exposure, persistence, browser, installed software CVEs (NVD/MSRC/EPSS/Grype model), repos. Read-only by default; every finding needs Evidence/Fix/Verify/Rollback and never prints secrets.
---

# Local Workstation Security Audit

Audit **máy trạm** (không phải codebase) trên Windows / macOS / Linux. Mục tiêu: tìm lỗ hổng vượt qua ranh giới tin cậy thật, xếp theo blast radius, mỗi finding kèm bằng chứng đo được + cách sửa + cách kiểm lại + rollback.

## Nguyên tắc bất biến

1. **Read-only trước, mutate sau.** Chỉ thay đổi hệ thống khi user chọn phương án cho từng finding.
2. **Không in secret ra output.** Chỉ ghi *tên biến + độ dài + vị trí*. Nếu buộc phải đọc giá trị (vd recovery key), ghi ra file ACL chặt, không echo. Lệnh nào có thể in value (`git config --get-regexp remote.*`, `git remote -v`, `manage-bde -status`) phải redact ngay trong pipeline.
3. **Không kết luận "không có/không mở" từ một phép đo hẹp.** Mỗi phép tìm phải kèm **positive control** (một thứ chắc chắn tồn tại mà phép đo phải tìm ra). Control = 0 kết quả ⇒ kênh đo hỏng, không phải hệ thống sạch.
4. **Phân biệt 3 trạng thái**: *đã kiểm và sạch* / *đã kiểm và có vấn đề* / **chưa kiểm được**. Trạng thái thứ ba ghi rõ lý do (thiếu quyền, không có kênh đo), không gộp vào "sạch".
5. **Verify bằng trạng thái, không bằng exit code.** `exit 0` không chứng minh gì; phải query lại state (registry, service, port, ACL, encryption status).
6. **Đo lại sau khi sửa.** Hệ thống khác có thể revert hoặc thay đổi không đạt mục tiêu (xem *Đo lại sau khi áp dụng*).
7. **Sửa gì cũng phải có rollback**, ưu tiên thay đổi nhỏ nhất tại điểm quyết định cuối.
8. **Đổi gì trên máy thì đồng bộ vào SSOT** nếu thay đổi được quản lý bằng IaC/GPO.
9. **Bắt buộc Scan CVE (Mandatory CVE Scanning)**: Full audit không được dừng ở patch-gap hay version check. Bắt buộc đối chiếu phiên bản cài đặt của OS, Browser, Remote-Access host, và phần mềm rủi ro cao với cơ sở dữ liệu lỗ hổng (NVD, MSRC, CISA KEV, EPSS) theo mô hình Grype pipeline (catalog → match → enrich → policy → report).
10. **CVE/IOC từ nguồn thứ cấp không phải bằng chứng ảnh hưởng.** Bản tin, blog, post-mortem, báo cáo vendor chỉ là *manh mối*. Ghi trạng thái `chưa đối chiếu` cho tới khi khớp NVD/GHSA/OSV/advisory chính thức của vendor với **version đang cài**; không viết "máy bị ảnh hưởng" từ một bản tin. Version nằm trong dải được nêu ⇒ finding "cần xác minh", chưa phải "đã bị khai thác". Không đưa CVE-ID chưa xác minh vào skill hay report như sự thật.

## Chế độ chạy

| Chế độ | Khi nào | Việc phải làm |
|---|---|---|
| **Guidance** | Hỏi một câu bảo mật, review một mục, triage | Chỉ dùng phần liên quan; không tạo report |
| **Full audit** | "đánh giá bảo mật máy", "audit toàn bộ" | Chạy đủ Phase 1→18 (bắt buộc kèm scan CVE phần mềm & browser) theo *Thứ tự thực thi* bên dưới, ghi report |

Trước khi bắt đầu: chốt **host, OS/version, user chạy, có quyền admin không, phạm vi** (máy này / thêm ổ khác / thêm repo).

### Thứ tự thực thi (full audit)

Số Phase là tên mục, **không** phải thứ tự chạy. Thứ tự đúng:

1. **Bước 0** — kiểm tra phiên bản skill.
2. **Thu thập** — Phase 1–6 (parent tự chạy) **song song** Phase 10–18 (slice A–D, xem *Chạy multi-subagent*). Chỉ đọc, không sửa.
3. **Lượt elevated** — gom mọi mục `Access denied` của bước 2 vào 1 script, xin phép user chạy 1 lần.
4. **Phase 7** — xếp mức toàn bộ finding (cả 1–6 lẫn 10–18).
5. **Phase 9** — ghi report đầy đủ.
6. **Phase 8** — triage từng finding với user, áp dụng, đo lại, cập nhật mục *Trạng thái khắc phục* trong report.

Không ghi report trước khi bước 2–3 xong: finding của Phase 10–18 phải nằm trong report và trong phiên triage.

### Kiểm tra phiên bản mới nhất & Hỏi cập nhật (Bước 0)

Trước khi chạy audit, Agent PHẢI kiểm tra xem bản cài đặt cục bộ có phải là mới nhất chưa:
1. Đọc version cục bộ: file `VERSION` trong thư mục skill (hoặc metadata git).
2. Lấy version mới nhất từ GitHub qua GitHub API hoặc git ls-remote:
   ```bash
   # Cách 1 (qua GitHub API / raw):
   curl -s "https://raw.githubusercontent.com/duhd/local-workstation-security-audit/main/VERSION"
   # Cách 2 (qua git remote tags nếu đã clone):
   git ls-remote --tags --refs https://github.com/duhd/local-workstation-security-audit.git
   ```
3. **Nếu có phiên bản mới hơn (Local < Remote)**:
   - Dừng lại 1 nhịp và hỏi người dùng:
     > *"Phát hiện phiên bản mới của skill: v<local> → v<remote>. Bạn có muốn cập nhật lên bản mới nhất trước khi chạy audit không?"*
   - Nếu người dùng đồng ý:
     - Nếu cài qua `npx skills`: chạy `npx skills update local-workstation-security-audit -g -y`
     - Nếu cài qua git clone: chạy `git -C <skill-dir> pull --ff-only` (và copy lại command nếu cần).
     - Tiếp tục chạy audit trên phiên bản mới.
   - Nếu người dùng từ chối: tiếp tục chạy phiên bản hiện tại.

### Chạy 2 lượt: non-admin trước, elevated sau

Đừng để phiên chết ở `Access denied`. **Lượt 1** chỉ dùng lệnh đọc được không cần admin (đã verify trên Windows):

```
Get-NetFirewallRule -DisplayName <name> | -Direction Inbound -Enabled True -Action Allow
netsh advfirewall firewall show rule name=<name> verbose      # LocalIP/RemoteIP/Edge traversal
Get-NetTCPConnection -State Listen ; Get-Process -Id <pid>
Get-SmbShare / Get-SmbSession / Get-SmbOpenFile / Get-SmbMapping / Get-Printer
Get-LocalUser / Get-LocalGroupMember / Get-LocalGroup
icacls <path> ; Get-Acl <path>
Get-ScheduledTask ; Get-CimInstance Win32_Service ; Get-Service
ssh-keygen -y -P "" -f <key>
git config --show-origin --get-all credential.helper ; git remote -v ; git log -S
tailscale status ; tailscale debug netmap
reg query <key> /s
```

**Lượt 2** (chỉ khi cần): `Get-BitLockerVolume`/`manage-bde`, `Get-Tpm`, `Confirm-SecureBootUEFI`, `Get-MpPreference` (kể cả `ExclusionPath`), `Get-MpComputerStatus`, event log, và mọi thay đổi service/ACL/account.

`Access denied` **không** nghĩa "không tồn tại" ⇒ ghi vào *chưa kiểm được*, chuyển sang lượt 2.

### Chạy multi-subagent (mặc định cho full audit)

18 phase chạy tuần tự sẽ đốt context và dễ bỏ sót. Parent tự chạy **Phase 1–6** (cần kết quả để làm CVE mapping và dedupe), còn **Phase 10–18** chia thành **4 slice độc lập**, mỗi subagent một slice, **tối đa 4 agent đồng thời**:

| Slice | Phase | Nội dung |
|---|---|---|
| **A** | 17 + 10 | bề mặt AI agent (MCP `command`/hook/`approvalMode`/transcript/daemon loopback) + danh tính (authorized_keys, Credential Manager/Keychain, shell history, auto-logon, LSA/Credential Guard, cached logons, `klist`) |
| **B** | 12 + 18 | secret trong artifact: tfstate/tfplan/tfvars, crash dump, editor backup, notebook output, Postman/Insomnia/HAR, Recycle Bin, shadow copy, `git fsck`/`git stash`, thư mục cloud sync + chuỗi cung ứng công cụ dev & credential triển khai (provenance installer Homebrew/scoop/choco, artifact "bài test" tuyển dụng, deploy token/service-account key/LLM key, update channel, clipboard) |
| **C** | 11 + 13 | thực thi code & privesc (PATH writable, service path/DACL, `SeImpersonate`, `AlwaysInstallElevated`, git hook/`include.path`/`insteadOf`, registry package manager, WSL/docker, native messaging, `.vscode/tasks.json`) + kênh tin cậy (root CA lạ, updater + quyền ghi binary, `winget source`, AppLocker/WDAC) |
| **D** | 14 + 15 + 16 | năng lực phát hiện (audit policy, PS 4104, Sysmon/AMSI, log retention/1102, forwarder health) + mạng ngoài listener (Wi-Fi auth type, LLMNR/NetBIOS/mDNS, `.lnk/.scf` trong repo, spooler/WebClient, proxy/PAC/DoH) + vật lý/pre-boot (auto-login, screen lock, boot order, hibernation, escrow) |

Giao theo thứ tự blast radius **A → B → C → D**, nhưng chạy song song được vì 4 slice không giao nhau.

**Hợp đồng bắt buộc trong prompt của mỗi subagent** (7 điều, copy nguyên văn — thiếu 1 điều là không nhận kết quả):

1. **READ-ONLY**: không sửa/xoá/tạo file, không đổi registry/ACL, không start/stop service.
2. **Không in secret**: chỉ đường dẫn, tên key, số lượng, độ dài, boolean. Không in nội dung key/token/PSK/env value.
3. **Positive control** cho mỗi phép tìm; control = 0 ⇒ ghi "kênh đo hỏng", không ghi "không có".
4. **3 trạng thái**: finding / đã kiểm sạch / chưa kiểm được (kèm lý do).
5. `Access denied` ⇒ "chưa kiểm (cần elevated)", **không** kết luận "không có".
6. Không chạy PoC, không gọi API ngoài, không thử dùng credential tìm được.
7. Output đúng 4 mục: `## Findings` (bảng: mục | bằng chứng lệnh+output | mức đề xuất | Fix | Verify | Rollback), `## Đã kiểm và sạch`, `## Chưa kiểm được`, `## Bẫy gặp phải`.

**Việc của parent — không delegate:**

- Là **người duy nhất ghi report**; dedupe finding trùng giữa các slice (cùng một nguyên nhân xuất hiện ở 2 slice ⇒ 1 dòng, ghi rõ 2 nguồn).
- Chuẩn hoá mức severity theo *Phase 7* — subagent chỉ **đề xuất**, parent quyết.
- Giữ **coverage ledger**: mỗi mục thuộc đúng 1 trong 3 trạng thái; mục "chưa kiểm" phải nêu lý do và bước chạy tiếp.
- Nếu một agent trả về mỏng, không có positive control, hoặc ghi "sạch" mà không kèm lệnh ⇒ **chạy lại slice đó** với phạm vi hẹp hơn. Không chấp nhận "sạch" thiếu bằng chứng.
- Ghi vào report slice nào đã chạy, slice nào chưa, và môi trường có subagent hay không.

**Cấm**: hai agent cùng sửa một file; agent tự apply fix (mọi mutation vẫn qua Phase 8 + quyết định của user); agent chạy phase ngoài slice của mình (trùng lặp ⇒ tốn và lệch số liệu).

**Không có tool subagent?** Chạy tuần tự Phase 1–6, rồi Phase 10–18 theo thứ tự ưu tiên *17 → 10 → 12 → 18 → 11 → 14 → 13 → 15 → 16*, và ghi rõ trong report là chạy đơn luồng.


## Phase 1 — Recon & posture

| Hạng mục | Windows | macOS | Linux |
|---|---|---|---|
| OS/build | `Get-CimInstance Win32_OperatingSystem` | `sw_vers` | `cat /etc/os-release; uname -a` |
| Patch | `(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count` | `softwareupdate -l` | `apt list --upgradable 2>/dev/null \| grep -c upgradable` / `dnf check-update` |
| Elevation | `whoami /groups \| findstr S-1-16-12288` | `id -u` (0=root) | `id -u` |
| Mã hoá ổ | `manage-bde -status C:` hoặc `Get-BitLockerVolume` | `fdesetup status`; `diskutil apfs list` | `lsblk -o NAME,FSTYPE,MOUNTPOINT`; `cryptsetup status <dev>`; `findmnt -no FSTYPE /` |
| TPM/secure boot | `Get-Tpm`; `Confirm-SecureBootUEFI` | `system_profiler SPiBridgeDataType`; `csrutil status`; `spctl --status` | `/sys/class/tpm/tpm0`; `mokutil --sb-state`; `bootctl status` |
| Firewall | `Get-NetFirewallProfile`; `netsh advfirewall show allprofiles` | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`; `pfctl -s rules` | `ufw status verbose` / `firewall-cmd --state` / `nft list ruleset` |
| UAC/sudo | `HKLM:\...\Policies\System` → `EnableLUA`, `ConsentPromptBehaviorAdmin` | `sudo -l`; `sysadminctl -secureTokenStatus <user>` | `sudo -l`; `ls /etc/sudoers.d` |
| AV/EDR | `Get-MpComputerStatus`; `root/SecurityCenter2` `AntiVirusProduct` | `systemextensionsctl list`; `ps aux \| grep -iE 'falcon\|sentinelone\|crowdstrike\|mdm'` | `systemctl list-units --type=service \| grep -iE 'falcon\|sentinel\|carbonblack\|wazuh\|osquery\|defender'` |

Không kết luận "đã vá đầy đủ" từ danh sách KB/`Get-HotFix` (bỏ sót cumulative/SSU) — dùng update searcher / `softwareupdate` / package manager.

### Patch gap của ứng dụng & browser (đừng bỏ)

OS patch ≠ ứng dụng patch. Máy có thể vá OS đầy đủ nhưng browser/remote-access host lệch nhiều major version.

| Việc | Windows | macOS | Linux |
|---|---|---|---|
| Gói có bản mới | `winget upgrade --include-unknown` | `brew outdated --greedy` | `apt list --upgradable` / `dnf check-update` / `flatpak remote-ls --updates` |
| Version browser đang cài | `(Get-Item "$env:ProgramFiles\Google\Chrome\Application\chrome.exe").VersionInfo.ProductVersion`; registry Uninstall keys | `defaults read "/Applications/Google Chrome.app/Contents/Info" CFBundleShortVersionString`; `mdls -name kMDItemVersion` | `google-chrome --version`; `chromium --version`; `firefox --version` |
| Bản mới nhất | Chrome: `https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1` (đã verify: `platform=Windows`/`Mac`/`Linux`; `Win` trả rỗng); Edge: `winget show Microsoft.Edge` | Chrome: `platform=Mac`; Safari theo OS | Chrome: `platform=Linux`; `apt-cache policy <pkg>` |
| Remote-access host | `winget list "*Remote Desktop*"`, `Get-Service chromoting`, RustDesk/AnyDesk | `ls /Applications | grep -iE 'anydesk|rustdesk|teamviewer'` | `systemctl status anydesk rustdesk --no-pager` |

Cách đọc: so **installed vs latest stable**. Patch release của browser (ví dụ `X.Y.Z.41` → `X.Y.Z.47`, cùng major) gần như luôn chứa bản vá bảo mật ⇒ lệch ≥1 patch = cần update. Remote-access host lệch **major** version trong khi service đang chạy là finding mức High nếu ổ chưa mã hoá.

Giới hạn phải nêu rõ trong report: **patch gap ≠ CVE mapping**. Muốn khẳng định "dính CVE-X" phải đối chiếu NVD/MSRC + release notes; nếu chưa làm thì ghi "lệch bản mới nhất, mức khai thác chưa xác định".

### CVE mapping (chỉ cho nhóm rủi ro cao)

Không map toàn bộ 500 app đã cài — vô nghĩa và tốn thời gian. Chỉ map nhóm mà CVE dẫn thẳng tới thực thi code hoặc chiếm máy:

1. browser (Chrome/Edge/Firefox/Safari) và engine của nó;
2. remote-access host (Chrome Remote Desktop, AnyDesk, RustDesk, TeamViewer);
3. OS component có bản vá tháng (Windows cumulative, driver đồ hoạ);
4. VPN/proxy client (WARP, Tailscale, OpenVPN);
5. trình đọc/giải nén file không tin cậy (7-Zip, PDF reader, Office).
6. AI gateway / LLM proxy / agent runtime (LiteLLM, Ollama, MCP server, framework agent): thường giữ key của nhiều provider và định tuyến cho nhiều người dùng ⇒ một CVE leo quyền ở đây mở khoá mọi key phía sau. Catalog: `pip list --format=json`, `npm ls -g --json`, `docker ps --format '{{.Image}}'`.

Nguồn (chỉ GET, không cần account). Ba biến thể dưới đây **đã chạy thật**; con số là giá trị kỳ vọng để làm positive control:

```
# 1) keyword + vendor — rộng, dùng khi chưa biết CPE  (200, 7.440 kết quả với ví dụ này)
https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=chrome&virtualMatchString=cpe:2.3:a:google&resultsPerPage=1

# 2) cpeName — CHỈ nhận version cụ thể  (200, 4.103 kết quả)
https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:google:chrome:120.0.6099.109:*:*:*:*:*:*:*&resultsPerPage=1

# 3) keyword thuần  (200, 7.819 kết quả)
https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=chrome&resultsPerPage=1

# Microsoft Security Update Guide (Edge, Windows component)  (200, 500 phần tử/trang)
https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability

# Chrome release notes — mỗi stable update liệt kê CVE đã vá
https://chromereleases.googleblog.com
```

**Bẫy đã đo, đừng mất thời gian**: `cpeName` với `*` ở trường version (`cpe:2.3:a:google:chrome:*:*:…`) trả **404**, và CPE rút gọn (`cpe:2.3:a:google:chrome`) cũng **404**. `cpeName` chỉ trả 200 khi có **version cụ thể** — và đó chính là thứ audit luôn có sẵn (version đang cài), nên dùng nó làm đường chính. Cần URL-encode dấu `:` (`cpe%3A2.3%3A...`) khi gọi từ shell.

Lưu ý về ví dụ 1: `keywordSearch` + `virtualMatchString` trả 200 nhưng kết quả **chủ yếu do keyword quyết định** (7.440 so với 7.819 của keyword thuần) — `virtualMatchString` chỉ thu hẹp theo vendor. Đừng đọc nó là "đã lọc đúng CPE"; muốn khớp chính xác phải dùng `cpeName` với version.

**404 ≠ endpoint hỏng**: NVD trả 404 khi CPE không có bản ghi hoặc sai định dạng. Luôn chạy positive control `?keywordSearch=chrome&resultsPerPage=1` (đo được **7.819**) trước khi kết luận; nếu positive control cũng 0/404 thì đó là mạng chứ không phải "máy không có CVE".

Rate limit NVD: **5 request / 30 giây** khi không có API key (50 nếu có) — chèn delay giữa các lần gọi, đừng vòng lặp dày.

**Cách đọc kết quả:**

1. Lấy version đang cài (đã có từ bước patch gap).
2. Với mỗi CVE trả về, đọc `configurations[].nodes[].cpeMatch[]`: nếu version đang cài thoả `versionStartIncluding ≤ installed < versionEndExcluding` ⇒ **còn ảnh hưởng**; nếu `installed ≥ versionEndExcluding` ⇒ **đã vá**.
3. Ghi vào report: `CVE-id`, CVSS + vector, `fixed version`, tên nguồn, **ngày truy vấn**, và kết luận `affected / patched / not applicable`.

**Luật:**

- **Positive control bắt buộc**: chạy `?keywordSearch=chrome&resultsPerPage=1` (đo được **7.819** kết quả) hoặc `?cpeName=<CPE có version cụ thể>` (đo được **200**). Nếu positive control cùng trả 0/404 ⇒ mạng bị chặn hoặc rate limit: ghi "chưa truy vấn được", **không** kết luận "không có CVE". (Nhớ: `cpe:2.3:a:google:chrome` rút gọn và mọi CPE có `*` ở trường version đều trả **404** — không dùng chúng làm control.)
- Không chạy PoC, không tải exploit, không thử khai thác để "xác nhận".
- Không gửi credential/PAT khi gọi API ngoài.
- Nếu version đang cài cũ hơn nhiều major (như remote-access host lệch 3 major), việc map từng CVE là không cần thiết — kết luận "lệch nhiều major, phải update" đã đủ mạnh và đúng.
- **Nguồn thứ cấp** (xem nguyên tắc 10): CVE nêu trong tin tức mà chưa tra được NVD/GHSA/OSV ⇒ ghi `chưa đối chiếu`, kèm alias nếu có (OSV có thể resolve qua alias GHSA/PYSEC trước khi NVD cập nhật). Chỉ nâng thành `affected` khi version đang cài thoả dải ảnh hưởng.
- **Vá đã cài ≠ vá đã có hiệu lực.** Kernel/libc/OpenSSL cần reboot hoặc restart service. Kiểm: Debian/Ubuntu `/var/run/reboot-required`; RHEL `needs-restarting -r`; so `uname -r` với kernel mới nhất đã cài (`rpm -q kernel --last` / `dpkg -l 'linux-image*'`); Windows `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`. Còn pending reboot ⇒ finding "chưa có hiệu lực", không ghi "đã vá".
- **Fix chưa có ở kênh stable** (distro mới có bản vá trong `-proposed`/chưa phát hành): ghi `fix.state = not-fixed-in-stable`, nêu biện pháp giảm thiểu (chặn port, tắt tính năng), không ghi "đã vá".

### Mô hình Grype áp cho máy trạm (5 bước)

Grype quét container/filesystem theo pipeline *catalog → match → enrich → policy → output*. Máy trạm không có SBOM sẵn, nên dựng "SBOM-lite" trước rồi đi đúng 5 bước đó:

**1. Catalog (SBOM-lite)** — liệt kê theo ecosystem, không đoán từ tên file:

| Nguồn | Lệnh |
|---|---|
| Windows package | `winget list --accept-source-agreements`; `Get-Package`; registry Uninstall |
| Windows driver | `Get-CimInstance Win32_PnPSignedDriver \| Select-Object DeviceName,DriverVersion` |
| macOS app | `brew list --versions`; `system_profiler SPApplicationsDataType` |
| Linux distro | `dpkg-query -W -f='${Package} ${Version}\n'` / `rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n'` / `apk info -v` / `snap list` / `flatpak list --columns=application,version` |
| Language runtime | `npm ls -g --depth=0 --json`; `pip list --format=json`; `gem list`; `cargo install --list`; `dotnet --list-runtimes`; `go version -m <bin>` |

Ghi `name | version | ecosystem | source`. Đây là artifact **stateful** — lưu cạnh report, không commit vào repo public.

**2. Match có version constraint** — chọn nguồn theo ecosystem (đừng dùng NVD cho mọi thứ):

| Ecosystem | Nguồn khớp | Đã đo |
|---|---|---|
| Distro package | USN / DSA / RHSA / ALAS — version scheme riêng, NVD không so được | – |
| App third-party | NVD: `keywordSearch` + `virtualMatchString=cpe:2.3:a:<vendor>` (200); `cpeName` chỉ khi có **version cụ thể** (200) | ✓ |
| Windows / Edge component | MSRC `https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability` | ✓ 200, 500 item/trang |
| npm / pip / go / cargo / gem | OSV `POST https://api.osv.dev/v1/query` (GET trả 405 — phải POST); GHSA `https://api.github.com/advisories?ecosystem=<eco>` | ✓ 405 ở GET nghĩa là endpoint sống |

Mỗi dòng kết quả phải có: `CVE/GHSA`, `installed`, `range` (`versionStartIncluding` / `versionEndExcluding`), `fix.version`, và **`fix.state`** = `fixed | wont-fix | unknown`.

**3. Enrich để xếp hạng** (Grype không xếp chỉ bằng CVSS):

- **EPSS**: `https://api.first.org/data/v1/epss?cve=CVE-…` → trả `epss` + `percentile`. **Đã đo: 200.**
- **CISA KEV**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` — **đo được 403 (trả HTML) từ mạng này**. Nếu bị chặn: ghi "chưa truy vấn được KEV", dùng EPSS + advisory vendor, **không** kết luận "không bị khai thác".
- Thứ tự ưu tiên: **KEV > EPSS ≥ 0.1 > CVSS cao nhưng EPSS thấp**.

**4. Policy / VEX** — tương đương `ignore` của Grype, nhưng có hạn:

```yaml
# .audit-vex.yaml, đặt cạnh report
- id: CVE-2023-XXXX
  package: some-tool
  reason: "không dùng tính năng bị ảnh hưởng; đã có compensating control X"
  expires: 2026-12-31
```

Mỗi lần chạy đọc lại file này; mục **quá `expires` tự nổi lên lại**. Không có `expires` ⇒ không được suppress.
Gate mặc định: flag khi `fix.state=fixed` **và** (`KEV` hoặc `EPSS ≥ 0.1` hoặc `CVSS ≥ 7`). `wont-fix` ⇒ đưa vào mục *accepted risk* kèm biện pháp bù, không im lặng bỏ.

**5. Output tái lập** — report phải ghi: timestamp truy vấn, tên + phiên bản nguồn dữ liệu (NVD/MSRC/EPSS), và CVE chia 3 nhóm `actionable / accepted / not-applicable`. Không có timestamp thì lần sau không so sánh được, và không ai biết kết luận cũ còn đúng không.

## Phase 2 — Bí mật nằm trên đĩa

| Nguồn | Windows | macOS / Linux |
|---|---|---|
| Git credential | `%USERPROFILE%\.git-credentials`; `git config --show-origin --get-all credential.helper` | `~/.git-credentials`, `~/.config/git/credentials`; macOS `security dump-keychain \| grep -c svce` (**chỉ đếm**, không `-w`/`-g` vì sẽ in mật khẩu); Linux `secret-tool search` (chỉ đếm kết quả) |
| Cloud/registry | `.aws\credentials`, `.docker\config.json`, `.kube\config`, `.config\gh\hosts.yml` | same paths in `~`; macOS `security find-generic-password -s <svc> >/dev/null 2>&1 && echo exists` (**không** dùng `-w`, sẽ in mật khẩu); Linux `secret-tool search --all <attr> <val> >/dev/null && echo exists` (**không** in value) |
| Agent/harness | `%USERPROFILE%\.<tool>\**`, `%APPDATA%\<tool>` | `~/.<tool>/**`, `~/Library/Application Support/<tool>` |
| SSH | `~/.ssh/*` | `~/.ssh/*`, `~/.gnupg` |
| Quyền file | `icacls <path>` — **không** dùng `ls -la` trong MSYS/Cygwin | `namei -l <path>`; `stat -c '%a %U:%G'`; macOS `ls -lO@` / `stat -f '%Lp %Su'` |

Bắt buộc kiểm thêm:

- **Passphrase private key**: `for k in ~/.ssh/*; do ssh-keygen -y -P "" -f "$k" >/dev/null 2>&1 && echo "NO_PASSPHRASE $k" || echo "ok $k"; done` (chỉ in trạng thái).
- **Credential nhúng trong URL**: xem Phase 6 (đừng dùng lệnh in value).
- **`.gitmodules` là file tracked**: `git ls-files --error-unmatch .gitmodules` rồi `git show HEAD:.gitmodules` — nếu có credential thì đã vào lịch sử.
- **Secret của process đang chạy**: browser automation (`DevToolsActivePort`), agent DB (SQLite `auth_credentials`), credential store riêng của tool.

## Phase 3 — Exposure mạng

1. Listener: `Get-NetTCPConnection -State Listen` / `ss -ltnp` / `lsof -nP -iTCP -sTCP:LISTEN`. Ghi rõ **bind address** (`127.0.0.1` vs `0.0.0.0`/`::`) và process sở hữu (PID 4/System = kernel/driver).
2. Rule inbound **đang bật**: `Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow` / `ufw status` / `pfctl -s rules`. `Get-NetFirewallRule` trả **cả rule disabled** ⇒ luôn kiểm `Enabled`.
3. Rule `Protocol=Any, LocalPort=Any` **không** xuất hiện khi lọc theo port ⇒ luôn có nhánh any-port riêng. `Get-NetFirewallPortFilter` hàng loạt cần admin; per-rule không. `netsh advfirewall firewall show rule name=X verbose` đọc được không cần admin và cho `LocalIP/RemoteIP/InterfaceTypes/Edge traversal` — dùng làm kênh thứ 2.
4. VPN/mesh: `tailscale status`, `tailscale debug netmap` (`PacketFilter`: `Srcs`, `Dsts`, port range, rule drop). ACL ở control plane có thể **rộng hơn** firewall host.
5. Chia sẻ/remote: SMB, NFS, AirDrop, RDP/VNC, WinRM — kiểm cả listener và rule.
6. Container/VM: `docker ps --format`, `wsl -l -v`, `~/.wslconfig`; xác định port publish ra host hay chỉ loopback.

Kết luận exposure phải nêu **đủ 2 lớp**: firewall host **và** lớp mạng (tailnet/LAN/public).

## Phase 4 — Persistence & khởi động

| Windows | macOS | Linux |
|---|---|---|
| `HKLM/HKCU \...\Run`, `RunOnce`, `WOW6432Node` | `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` | `systemctl list-unit-files --state=enabled`, `~/.config/systemd/user` |
| `Winlogon\Shell/Userinit/Notify`, `AppInit_DLLs`, `IFEO\...\Debugger` | `launchctl list` | `crontab -l`, `/etc/cron.*`, `~/.config/autostart` |
| Scheduled Tasks (ngoài `\Microsoft\`) | Login items (`osascript -e 'tell application "System Events" to get the name of every login item'`) | `/etc/rc.local`, `init.d` |
| `Win32_Service StartMode=Auto` | `systemextensionsctl list` | `systemctl list-units --type=service` |
| Startup folder | `/Library/StartupItems` | user autostart |

Mỗi entry: **resolve target** (path thật + args), **chữ ký/hash**, **quyền thư mục chứa** (path user-writable + chạy SYSTEM/Highest = điểm persistence thật), phân biệt entry có binary với **COM handler** (không có `Execute`).

## Phase 5 — Browser

- Liệt kê **profile** + kích thước `Login Data`/`Cookies` + extension (map `__MSG_*` sang tên thật từ `manifest.json`).
- Đường dẫn: Win `%LOCALAPPDATA%\<Vendor>\<Browser>\User Data`; macOS `~/Library/Application Support/<Vendor>/<Browser>`; Linux `~/.config/<vendor>/<browser>`.
- Remote-access host: Chrome Remote Desktop (`chromoting`), RustDesk, AnyDesk — kiểm service + extension.
- **Shadow Automation Browser & Engine Cache (Playwright/Puppeteer/Agent-browser)**:
  - Quét cache Chromium mà Agent tải riêng: Windows `%LOCALAPPDATA%\ms-playwright`, `%USERPROFILE%\.cache\puppeteer`; macOS `~/Library/Caches/ms-playwright`; Linux `~/.cache/ms-playwright`.
  - So sánh version build Chromium ẩn này với bản stable Chrome chính thức (nếu lệch nhiều tháng ⇒ **nguy cơ lỗ hổng V8/GPU Sandbox Escape**).
  - Kiểm tra cờ khởi chạy browser của Agent: có bị chèn `--no-sandbox` hoặc `--disable-setuid-sandbox` không.
- PWA tự chạy khi login: đọc shortcut → `--app-id=<id>` → tìm `Web Applications/_crx_<id>/` để biết app nào.
- Không cố giải mã `Login Data`; kết luận theo *khả năng truy cập file*, không theo nội dung.

## Phase 6 — Repo & lịch sử git

```bash
# tìm repo (tăng maxdepth theo máy; ghi lại độ sâu đã quét)
find ~ -maxdepth 4 -name .git 2>/dev/null | sed 's#/.git$##'   # không -type d: worktree/submodule có .git là FILE

# 1) remote — LUÔN redact, vì remote.*.url có thể chứa user:token
git -C <repo> remote -v | sed -E 's#://[^@/]+@#://<redacted>@#'

# 2) config cấp repo — CỐ Ý loại trừ remote.* (get-regexp in cả value ⇒ sẽ đổ token ra log)
git -C <repo> config --local --get-regexp '^(credential|http\.|url\.)'

# 3) .gitmodules — chỉ in TÊN FILE (-l), không -o/-h
# -print0/xargs -0: path có dấu cách; -r: không có file thì không chạy grep (grep không đối số sẽ treo chờ stdin)
find ~ -maxdepth 4 -name .gitmodules -print0 2>/dev/null | xargs -0 -r grep -lE '://[^/[:space:]]+:[^/[:space:]]+@'
```

Nếu credential nằm trong **file tracked**:

1. `git ls-files --error-unmatch <file>` → tracked?
2. `git show HEAD:<file>` → có trong HEAD?
3. `git log -S "<pattern>" --oneline -- <file>` → commit nào đưa vào.
4. `git branch -r --contains <commit>` → **đã push lên nhánh nào**; `git merge-base --is-ancestor <commit> origin/<branch>`.
5. Kết luận mức: chỉ working tree → sửa file đủ; đã commit → revoke + (tuỳ) rewrite; đã push → **revoke bắt buộc**, rewrite chỉ khi user duyệt.

Rewrite đúng cách (không xoá file): `git filter-repo --replace-text patterns.txt` với `oauth2:[^@[:space:]]+@==>oauth2:<REDACTED>@`. **Không** dùng `--invert-paths --path .gitmodules`.

## Phase 7 — Severity & xếp hạng

Xếp theo **blast radius**, không theo thứ tự checklist.

| Mức | Neo |
|---|---|
| **Critical** | Từ xa, không cần auth, leo thang toàn bộ (code exec, chiếm mọi account) |
| **High** | Vượt hẳn một kiểm soát có chủ đích: đĩa không mã hoá chứa credential prod; đọc credential của principal khác (sandbox↔user); token đã publish; SMB admin share mở cho mạng không tin cậy |
| **Medium** | Vượt ranh giới nhưng blast radius hẹp / cần điều kiện phụ / chỉ trong cùng một user |
| **Low** | Lộ thông tin nội bộ không phải secret, hoặc ảnh hưởng biên |
| **Informational** | Quan sát đúng nhưng chỉ có nghĩa như tiền đề |

Không gán mức cho mục **chưa kiểm được**. Nếu chưa chứng minh được điều kiện khai thác, ghi "exposure tiềm năng, kích hoạt bằng X".

Quy đổi sang nhãn ưu tiên dùng trong report và triage: **Critical = P0 · High = P1 · Medium = P2 · Low = P3**. Informational không có nhãn P và không đưa vào triage (chỉ liệt kê trong report).

## Phase 8 — Remediation (theo quyết định của user)

Chạy **sau** khi report Phase 9 đã ghi (xem *Thứ tự thực thi*); kết quả áp dụng cập nhật ngược vào mục *Trạng thái khắc phục* của report.

Với **từng** finding, Agent PHẢI đưa người dùng vào một giao diện lựa chọn tường minh — không được tự suy đoán phương án. Có **hai nhánh**, chọn theo tool thực có trong harness đang chạy:

**Nhánh A — Harness có Ask Question tool** (`ask` / `AskUserQuestion`): BẮT BUỘC gọi tool đó.
- **Tuần tự từng finding riêng biệt (1 finding = 1 câu hỏi, TUYỆT ĐỐI KHÔNG BATCH gom cụm finding lại)**: Duyệt lần lượt theo thứ tự blast radius P0 → P1 → P2 → P3. Mỗi finding là một lượt gọi tool hoặc một câu hỏi đơn lẻ để người dùng đưa ra quyết định độc lập, có đủ không gian đọc kỹ bằng chứng và lệnh sửa.
- **Các options chuẩn bắt buộc cung cấp cho mỗi finding**:
  1. `Accept`: Chấp nhận rủi ro (kèm phân tích hệ quả của việc không sửa).
  2. `Fix tối thiểu`: Sửa bề mặt trực tiếp, ít rủi ro phá vỡ chức năng.
  3. `Fix triệt để`: Đóng triệt để rủi ro (kèm cảnh báo tác động phá chức năng nếu có).
- Mỗi option phải có `description` nêu rõ: lệnh cụ thể sẽ chạy, hệ quả, cách rollback.

**Nhánh B — Harness không có tool đó** (Codex CLI, Cursor, Windsurf, Cline, Claude Desktop, hoặc bất kỳ client chỉ chat thuần): trình bày menu **đánh số** cho từng finding và dừng chờ người dùng trả lời rõ ràng (số hoặc tên phương án):
```text
[P1] <tên finding>
  1) Accept        — <hệ quả của việc không sửa>
  2) Fix tối thiểu — <lệnh> | tác động: <...> | rollback: <...>
  3) Fix triệt để  — <lệnh> | tác động: <...> | rollback: <...>
Chọn 1 / 2 / 3 (hoặc "bỏ qua" để sang finding tiếp theo):
```
Không được tự chọn thay người dùng ở cả hai nhánh. Nếu chạy non-interactive (CI, batch, cron) → dừng ở chế độ **read-only report** và ghi rõ "chưa áp dụng remediation: không có kênh xác nhận".

### Thứ tự bắt buộc khi nhiều lớp

1. **Revoke credential** trước — đây là việc duy nhất thực sự đóng lỗ (token/refresh token đã publish thì sửa file không cứu được).
2. **Siết quyền/ACL** (chặn principal khác đọc secret).
3. **Rewrite lịch sử / tắt service / đổi config** sau cùng — chỉ giảm phơi nhiễm tương lai.

Làm ngược thứ tự (sửa file → quên revoke) là lỗi phổ biến nhất.

**Credential đã bị sao chép thì cập nhật không cứu được.** Nếu một bản cài/update nhiễm (installer, updater, plugin) từng chạy trên máy, mọi secret nó đọc được (shadow/SSH key/`my.cnf`/shell history/token trong `.env`) coi như **đã lộ** ⇒ rotate toàn bộ, đo lại bằng credential **cũ** phải fail. Lên bản vá chỉ ngăn lần lây sau.

### Luật thực thi

1. Việc cần admin → gom vào **một** script, chạy elevated (`Start-Process -Verb RunAs -Wait -PassThru` / `sudo`), `Start-Transcript` ra temp, rồi **đọc log** và verify bằng state.
2. Nếu user từ chối UAC/sudo → báo "chưa áp dụng", không ghi như đã làm.
3. Thao tác không hoàn tác được (force-push, xoá dữ liệu, disable service đang dùng) → **hỏi trước**, nêu ảnh hưởng tới người/máy khác.
4. Việc sinh secret (BitLocker recovery password): tạo **trước** khi mã hoá, ghi file ACL chặt, escrow nếu môi trường cho phép, **assert định dạng** trước khi xoá key cũ.
5. Dọn dẹp: xoá script/log tạm. Nếu log từng chứa secret → coi như đã lộ, rotate lại.

### Đo lại sau khi áp dụng (bắt buộc)

Mỗi thay đổi phải được đo lại **bằng đúng phép đo đã dùng để phát hiện**, và ghi cả *trước/sau*:

| Thay đổi | Đo lại | Vì sao có thể không đạt |
|---|---|---|
| Tắt service | Listener còn không? `Get-NetTCPConnection -LocalPort <p>` | Port có thể do kernel/driver giữ (owner PID 4/System) — tắt service không đóng port |
| Disable account | `Get-LocalUser`/`passwd -S`/`dscl` sau lần chạy kế tiếp của service liên quan | Service provisioner (agent sandbox platform, MDM, EDR) có thể tạo lại account |
| Deny ACL | Đo lại **sau khi restart process đang giữ handle** | DENY chỉ áp cho handle mở **sau** đó; process đang mở file vẫn đọc được |
| Chặn port | Test từ máy khác ở cả IPv4 và IPv6 | Rule chỉ phủ một họ địa chỉ |
| Mã hoá ổ | `manage-bde -status` / `fdesetup status` / `cryptsetup status` | Có thể cần reboot; `UsedSpaceOnly` báo 100% nhưng free space vẫn plaintext |
| Rotate credential | Gọi thử bằng credential **cũ** phải fail (nếu môi trường cho phép kiểm an toàn) | Credential cũ vẫn hiệu lực tới khi server thu hồi |

### Playbook thường gặp

| Việc | Fix | Verify | Rollback |
|---|---|---|---|
| Block port từ dải mạng | `New-NetFirewallRule -Direction Inbound -Protocol TCP -LocalPort <p> -RemoteAddress <cidr> -Action Block` / `ufw deny from <cidr> to any port <p>` | `netsh advfirewall firewall show rule name=<n> verbose`; test từ máy khác | `Remove-NetFirewallRule -DisplayName <n>` / `ufw delete deny ...` |
| Chặn principal khác đọc secret | `icacls <path> /deny "<group>:(RX)"` / `setfacl -m g:<group>:- -R <path>` / `chmod 600` | `icacls <path>` thấy `(DENY)` trước `(I)`; `getfacl`; **đo lại sau khi restart process** | `icacls <path> /remove:d <group>` / `setfacl -x` |
| Disable account | `Disable-LocalUser -Name <u>` / macOS `sudo pwpolicy -u <u> -disableuser` (**không** dùng `dscl . -delete` — đó là xoá account, không hoàn tác được) / `usermod -L <u>` | `Get-LocalUser` / `dscl . -read /Users/<u> AuthenticationAuthority` thấy `;DisabledUser;` / `passwd -S`; kiểm lại sau khi service provisioner chạy | `Enable-LocalUser` / `sudo pwpolicy -u <u> -enableuser` / `usermod -U` |
| Credential helper | `manager` (Win) / `osxkeychain` (mac) / `libsecret` (Linux) | `git config --show-origin --get-all credential.helper` | đặt lại helper cũ |
| BitLocker | recovery password **trước** → TPM → escrow | `manage-bde -status` → `Protection On` + `Fully Encrypted` | `Disable-BitLocker` |
| FileVault | `fdesetup enable` (lưu recovery key) | `fdesetup status` | `fdesetup disable` |
| LUKS | kiểm `cryptsetup status <dev>` trước khi cài | `lsblk -f` | n/a |


### Hướng dẫn Hardening chủ động (Proactive Baseline Hardening) — Tùy biến theo từng OS

Ngoài việc sửa các finding sau khi phát hiện lỗi (Reactive Remediation), một máy trạm cho Dev / DevOps / Staff PHẢI được áp dụng bộ cấu hình an ninh phòng ngừa chủ động (Proactive Hardening Baseline) thiết kế chuyên biệt cho từng hệ điều hành:

#### 1. Windows Hardening Baseline (PowerShell / Admin)

| Nhóm kiểm soát | Mục tiêu an ninh | Lệnh cấu hình khuyến nghị | Rollback |
|---|---|---|---|
| **LSA Protection (RunAsPPL)** | Chống inject code và dump credential từ LSASS (Mimikatz) | `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 2 -Type DWord` rồi **reboot** (`2` = không UEFI lock, chỉ có hiệu lực từ Windows 11 22H2; `1` = có UEFI lock, registry không gỡ được) | `Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'` (hoặc đặt `0`) rồi reboot. **Không** đặt `1` khi rollback — `1` là bật kèm UEFI lock |
| **Credential Guard** | Cô lập NTLM/Kerberos hash trong VBS enclave | Bật GPO `Computer Configuration -> Administrative Templates -> System -> Device Guard` | Tắt policy |
| **Poisoning Defense** | Tắt LLMNR và NetBIOS broadcast (chống NTLM Relay) | `New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force; Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Type DWord` | Xoá value `EnableMulticast` |
| **Memory Dump Hygiene** | Tắt Fast Startup & Hibernation để RAM không lưu xuống đĩa unencrypted | `powercfg /h off` | `powercfg /h on` |
| **Print Spooler** | Tắt Print Spooler (chống PrintNightmare) nếu không dùng máy in | `Set-Service Spooler -StartupType Disabled; Stop-Service Spooler` | `Set-Service Spooler -StartupType Automatic; Start-Service Spooler` |
| **Attack Surface Reduction** | Chặn Office spawn child process & đánh cắp credential từ LSASS | `Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a,9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled,Enabled` (dùng `Add-`, **không** `Set-`: `Set-MpPreference` ghi đè toàn bộ danh sách ASR đang có). Rule LSASS thừa nếu đã bật RunAsPPL. Verify: `(Get-MpPreference).AttackSurfaceReductionRules_Ids` | `Remove-MpPreference -AttackSurfaceReductionRules_Ids <id>` |
| **SMB Security** | Tắt SMBv1, ép buộc SMB Signing | `Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force` | Đặt lại giá trị cũ |
| **UAC Strictness** | Bắt buộc nhập mật khẩu khi chạy tác vụ Administrator | `Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 1 -Type DWord` (`1` = hỏi credential trên secure desktop; `2` chỉ hỏi Yes/No) | Đổi lại về `5` (mặc định: hỏi consent cho binary không phải của Windows) |
| **Dev PATH Hygiene** | Đưa các thư mục user-writable (`AppData\Local\...`) xuống sau `System32` | Sửa lại thứ tự trong biến môi trường Machine `PATH` qua System Properties hoặc `setx` | Sắp xếp lại |

#### 2. macOS Hardening Baseline (Zsh / sudo)

| Nhóm kiểm soát | Mục tiêu an ninh | Lệnh cấu hình khuyến nghị | Rollback |
|---|---|---|---|
| **System Integrity (SIP)** | Đảm bảo SIP (rootless) luôn ở trạng thái bật | Kiểm tra `csrutil status`. Nếu disabled, phải vào Recovery Mode bật lại: `csrutil enable` | `csrutil disable` (chỉ trong Recovery) |
| **Gatekeeper & Notarization** | Chặn chạy app chưa được Apple ký số & xác minh | `sudo spctl --master-enable` | `sudo spctl --master-disable` |
| **Firewall (ALF)** | Bật Application Firewall và chế độ Stealth mode | `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on`<br>`sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on` | `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off` |
| **FileVault Key Hygiene** | Huỷ key FileVault khỏi RAM khi máy vào chế độ Standby/Sleep | `sudo pmset -a destroyfvkeyonstandby 1` | `sudo pmset -a destroyfvkeyonstandby 0` |
| **Remote Access Shutdown** | Tắt Remote Login (SSH) và Remote Management (VNC) nếu không dùng | `sudo systemsetup -setremotelogin off`<br>`sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop` | `sudo systemsetup -setremotelogin on` |
| **Sudo Password Caching** | Không dùng NOPASSWD và giới hạn thời gian nhớ mật khẩu sudo | Xoá các file cấp quyền tự do trong `/etc/sudoers.d/`, cấu hình `timestamp_timeout=0` | Khôi phục cấu hình sudoers |
| **Dev Tooling Paths** | Kiểm tra file cấu hình PATH trong `/etc/paths` và `~/.zshrc` | Đảm bảo `/usr/bin`, `/bin` luôn đứng trước các thư mục home user (`~/.bin`, `/usr/local/bin`) | Điều chỉnh lại file `.zshrc` |

#### 3. Linux Hardening Baseline (Bash / sudo)

| Nhóm kiểm soát | Mục tiêu an ninh | Lệnh cấu hình khuyến nghị | Rollback |
|---|---|---|---|
| **Kernel Ptrace Scope** | Ngăn process user đọc/dump bộ nhớ của process khác | `sudo sysctl -w kernel.yama.ptrace_scope=2`<br>(Ghi vào `/etc/sysctl.d/10-ptrace.conf` để giữ sau reboot) | `sudo sysctl -w kernel.yama.ptrace_scope=0` |
| **Core Dumps Restriction** | Vô hiệu hoá sinh file crash dump chứa memory secret | Thêm `* hard core 0` vào `/etc/security/limits.conf` và `fs.suid_dumpable = 0` vào sysctl | Xoá cấu hình limits |
| **Host Firewall (UFW/nft)** | Thiết lập Default Deny cho toàn bộ inbound traffic | `sudo ufw default deny incoming`<br>`sudo ufw default allow outgoing`<br>`sudo ufw enable` | `sudo ufw disable` |
| **SSH Daemon Hardening** | Tắt đăng nhập password, cấm root, chỉ nhận key có passphrase | Trong `/etc/ssh/sshd_config`: `PermitRootLogin no`, `PasswordAuthentication no`, `MaxAuthTries 3` | Đặt lại `yes` và restart sshd |
| **mDNS / LLMNR Shutdown** | Tắt Avahi và LLMNR chống broadcast poisoning | `sudo systemctl stop avahi-daemon; sudo systemctl disable avahi-daemon`<br>Trong `/etc/systemd/resolved.conf`: đặt `LLMNR=no` | `sudo systemctl enable avahi-daemon` |
| **Docker Socket Isolation** | Không đưa user dev vào group `docker` (root-equivalent trên Linux) | `sudo gpasswd -d <user> docker` (dùng rootless docker hoặc podman thay thế) | `sudo usermod -aG docker <user>` |
| **Kernel Module Lockdown** | Bật module verification và lockdown nếu kernel hỗ trợ | Thêm `lockdown=integrity` vào kernel boot parameters (GRUB) | Xoá param trong GRUB |

#### 4. AI Agent & Toolchain Hardening (Áp dụng chung mọi OS)
- **Agent Execution Sandbox**: Cấm chạy các harness AI ở chế độ `yolo` / `auto-accept` trên các thư mục dự án lạ. Luôn cấu hình `commandConfirmation: always`.
- **MCP Server Pinning**: Không dùng tag `@latest` hoặc `uvx` tự động kéo package mới trong cấu hình `.mcp.json`. Luôn ghim SHA hoặc version cụ thể để chống tấn công chuỗi cung ứng (Supply Chain).
- **Vault Isolation**: Tuyệt đối không lưu secret/key trong biến môi trường vĩnh viễn (`.bashrc`, `.zshrc`, Machine Environment). Sử dụng SOPS, Vault CLI hoặc 1Password CLI để inject token theo phiên làm việc.
## Phase 9 — Report

Ghi `docs/security/<YYYY-MM-DD>-local-workstation-security-audit.md` (hoặc đường dẫn user chọn). **Bắt buộc full ngay từ đầu**: Report audit và Báo cáo phân tích CVE lỗ hổng phần mềm/trình duyệt/OS PHẢI được xuất bản ĐẦY ĐỦ NGAY LẬP TỨC trong cùng một lần chạy, không được tách rời hay để chờ user yêu cầu mới làm.

Cấu trúc báo cáo bắt buộc:

1. **Metadata**: host, OS/build, user, quyền, ngày, phạm vi.
2. **Kết luận**: bảng xếp theo blast radius (P0→P3), cột *Tác động quan sát được* — không dùng "có thể" khi đã đo được.
3. **Báo cáo Lỗ hổng & CVE (OS, Browser, Remote-Access & High-Risk Apps)**: Bảng định danh CVE chi tiết cho các phần mềm rủi ro cao (Chrome, Edge, CRD Host, Git, 7-Zip, OS cumulative patch...), chỉ số CVSS, EPSS (xác suất khai thác), CISA KEV (cờ đang bị tấn công), và phân loại fix.state / unpatched.
4. **Chi tiết từng finding posture & attacker-first**: Evidence (lệnh + output) → Đánh giá → Fix → Verify → Rollback.
5. **Trạng thái khắc phục**: đã áp dụng (kèm verify) / đã thử và rollback (kèm lý do) / còn chờ (kèm điều kiện).
6. **Kết luận đã bị bác bỏ**: giữ lại để người sau không lặp lại.
7. **Giới hạn coverage**: Liệt kê chi tiết các mục chưa kiểm được và lý do (chủ yếu do thiếu quyền Administrator / UAC).
8. **Lượt elevated (Bắt buộc, chạy TRƯỚC khi ghi report — bước 3 của *Thứ tự thực thi*)**:
   - Main Agent rà toàn bộ mục bị chặn bởi `Access denied` trong bước thu thập (như `vssadmin list shadows`, `auditpol`, `secedit`, `Get-AppLockerPolicy`, quyền private key CA, kiểm tra sâu BitLocker/TPM).
   - **Bắt buộc chủ động hỏi user để xin phép chạy 1 đợt script elevated duy nhất qua UAC / sudo**, đưa kết quả đo thực tế vào report.
   - Mục nào vẫn không chạy được (user từ chối UAC, không có sudo) → giữ ở *Giới hạn coverage* kèm lý do.
9. **Hướng dẫn tiếp theo (Interactive Remediation Triage)**: Bắt buộc đính kèm đoạn prompt mẫu ở cuối report để người dùng copy dán cho Agent thực hiện phiên hỏi - đáp lựa chọn phương án (Accept / Fix) cho từng finding — theo đúng 2 nhánh ở Phase 8 (Ask Question tool nếu harness có, menu đánh số nếu không).
Prompt mẫu bắt buộc phải có ở cuối report:
```markdown
## Hướng dẫn tiếp theo: Chạy Interactive Remediation Triage

> "Dựa trên báo cáo audit vừa hoàn thành, hãy đóng vai trò chuyên gia an ninh hệ thống và lần lượt hỏi tôi về TỪNG finding riêng lẻ (1 finding = 1 câu hỏi, tuyệt đối không gom cụm / batch, theo thứ tự từ P0, P1 đến P3). Nếu harness đang chạy có công cụ Ask Question (`ask` / `AskUserQuestion`) thì BẮT BUỘC gọi tool đó cho từng finding; nếu không, in menu đánh số cho từng finding và dừng chờ tôi trả lời trước khi sang finding tiếp theo. Với mỗi finding cung cấp rõ 3 options:
> 1. Phương án Accept (chấp nhận rủi ro, phân tích hệ quả của việc không sửa).
> 2. Phương án Fix tối thiểu (sửa bề mặt, ít rủi ro phá vỡ chức năng, kèm lệnh sẽ chạy và rollback).
> 3. Phương án Fix triệt để (đóng triệt để rủi ro, kèm lệnh sẽ chạy, cảnh báo tác động phá chức năng nếu có và rollback).
> Chỉ thực thi phương án khi tôi đã chọn cho finding đó."
```

**Phân loại dữ liệu report**: report chứa IP tailnet/LAN, hostname, tên gateway, endpoint nội bộ, đường dẫn credential — coi là **tài liệu nội bộ**. Không push sang remote công khai; nếu repo có nhiều remote, chỉ push nhánh lên remote nội bộ.

Trước khi bàn giao: grep report cho `sk-`, `ghp_`, `ya29.`, `-----BEGIN`, `\d{6}(-\d{6}){7}`, `://[^/]+:[^/]+@` và redact nếu hit.

## Bảng bẫy đã cắn thật (bắt buộc đọc)

| Bẫy | Triệu chứng | Cách đúng |
|---|---|---|
| Filter hẹp ⇒ false negative | "không có rule allow port X" nhưng rule `Port=Any` đang mở | Luôn có nhánh `Any` + positive control |
| `Get-NetFirewallRule` trả rule disabled | Tưởng đang mở | Luôn kiểm cột `Enabled` |
| `ls -la` trong MSYS/Cygwin | Mọi file "777" | `icacls`/`Get-Acl`; mac `stat -f %Lp`; Linux `stat -c %a` |
| Bash tool redact output | Thấy `[REDACTED]` tưởng là nội dung file | Đọc lại bằng tool `read` |
| Tắt service ≠ đóng port | Port vẫn listen, owner PID 4/System | Kiểm `OwningProcess`; port do driver giữ |
| DENY chỉ áp handle mới | Vẫn thấy process cũ đọc được | Restart process sau khi đặt ACL; đo bằng `Accesschk`/logon thật |
| "0 share/0 session" ≠ không ai dùng | Tắt SMB server rồi mới biết IT cần `ADMIN$` | Kiểm client-side (`Get-SmbMapping`, printer port UNC) + hỏi IT trước |
| "Không có event log" ≠ không có telemetry | Bỏ sót Splunk/Wazuh/ManageEngine forwarder | Liệt kê service log-shipper |
| Provisioner service | Account vừa disable tự bật lại | Tìm service quản lý (agent sandbox platform, MDM, EDR); kiểm lại sau lần chạy kế tiếp |
| Cmdlet parameter set | `Enable-BitLocker -TpmProtector -RecoveryPasswordProtector` → "Parameter set cannot be resolved" | `(Get-Command X).ParameterSets`; tách lời gọi |
| Cmdlet in secret ra console | Recovery password lọt transcript | Lấy từ object trả về, không `Out-String`; assert định dạng; grep log bằng regex trước khi đọc |
| Escrow bị GPO chặn | `Group policy does not permit...` | Kiểm `dsregcmd /status` trước; fallback lưu ngoài máy |
| `-UsedSpaceOnly` | Báo 100% nhưng free space vẫn plaintext | Quyết định rõ used-space hay full |
| DENY vs inherited | Thấy `(I)(RX)` tưởng còn hở | DENY thắng; nhưng chủ sở hữu vẫn đọc được — đúng thiết kế |
| Credential trong file tracked | Chỉ sửa working tree | `git show HEAD:<file>` + `log -S` + `branch -r --contains` |
| MSYS path (`/c/...`) khi gọi `git.exe` | Git báo "No such file" | Dùng đường dẫn Windows trong PowerShell, hoặc `Push-Location` |
| `git config --get-regexp remote.*.url` | Token bị in nguyên văn | Loại `remote.*` khỏi regex; `git remote -v \| sed` redact |

## Không được làm

- Không thử credential/PAT thu được bằng cách gọi API thật (đó là hành vi dùng credential).
- Không probe hạ tầng/endpoint của tổ chức hoặc máy khác, không quét mạng nội bộ khi chưa được phép. **Được phép**: GET tới nguồn dữ liệu công khai mà skill chỉ định (GitHub `VERSION`, NVD, MSRC, EPSS, OSV, GHSA, chromiumdash) — không kèm credential.
- Không in nội dung secret, kể cả "để chứng minh".
- Không xoá/đổi file của người khác; không force-push branch đã publish mà chưa được duyệt.
- Không tuyên bố "đã audit xong toàn bộ" — luôn nêu coverage và phần chưa kiểm.

## Phạm vi bổ sung — attacker-first (Phase 10–18)

Phase 1–9 phủ *cấu hình nhìn thấy được*. Phần dưới là những gì kẻ tấn công thật sự dùng trên một máy dev workstation, và thường **bị bỏ sót** vì không nằm trong checklist posture. Chạy **trong bước thu thập**, song song với Phase 1–6 và **trước** Phase 7/9 (xem *Thứ tự thực thi*) — finding ở đây phải vào report và phiên triage. Chế độ Guidance có thể chọn từng mục theo mục tiêu tấn công.

Nguyên tắc chung: mỗi mục trả lời "kẻ tấn công được gì nếu mục này hở", và chỉ ghi *sự tồn tại + quyền*, không in giá trị.

### Phase 10 — Danh tính & vật liệu phiên (ai còn vào được máy này?)

| Kẻ tấn công dùng để | Kiểm | Windows | macOS | Linux |
|---|---|---|---|---|
| Duy trì đăng nhập SSH vĩnh viễn | Ai nằm trong `authorized_keys` (kể cả key lạ) | `~/.ssh/authorized_keys`, `authorized_keys2`; `ssh-keygen -lf` từng key (chỉ fingerprint) | `~/.ssh/authorized_keys` | `~/.ssh/authorized_keys`, `/etc/ssh/authorized_keys.d` |
| Pivot qua SSH config | `ProxyCommand`/`LocalCommand` trỏ binary lạ | `~/.ssh/config` | same | same |
| Lấy credential đã lưu | Credential Manager + DPAPI blob | `cmdkey /list`; `%APPDATA%\Microsoft\Credentials`, `%LOCALAPPDATA%\Microsoft\Credentials` | Keychain: `security dump-keychain \| grep -c svce` | `secret-tool search --all x y`; `~/.local/share/keyrings` |
| Đọc secret user từng gõ | Shell history | `(Get-PSReadLineOption).HistorySavePath` → grep pattern token | `~/.zsh_history`, `~/.bash_history` | same |
| Lấy mật khẩu cleartext lúc boot | Auto-logon | `Winlogon` → `AutoAdminLogon=1`, `DefaultPassword` (**cleartext**) | login items + FileVault auto-login | `getty` autologin, `~/.config/autostart` |
| Dump credential từ memory | LSA protection / Credential Guard / WDigest | `RunAsPPL`, `LsaCfgFlags`, `UseLogonCredential` | SIP (`csrutil status`) | `kernel.yama.ptrace_scope`, `lockdown` |
| Dùng lại hash/cache | Cached logons + policy | `CachedLogonsCount`, `net accounts` | `pwpolicy` | `pam_unix`/`faillock`, `/etc/security/pwquality.conf` |
| Vé Kerberos còn sống | Ticket cache — **chỉ đếm**, không in nội dung vé | `klist \| Select-String "Ticket"` (hoặc `klist \| find /c "Ticket"`) | n/a | `klist` (chỉ đếm dòng) |

### Phase 11 — Bề mặt thực thi code & leo thang đặc quyền

| Kẻ tấn công dùng để | Kiểm | Lệnh gợi ý |
|---|---|---|
| PATH hijack: thả binary vào dir đứng trước | Thư mục trong `PATH` mà user ghi được | `$env:PATH -split ';'` → `icacls <dir>`; macOS/Linux: `echo $PATH \| tr ':' '\n'` → `ls -ld` |
| Chạy binary thay cho service | Service path **không** quote + thư mục ghi được | `Get-CimInstance Win32_Service \| ? { $_.PathName -notmatch '^"' }` → kiểm `icacls` từng path |
| Sửa service config | Service DACL cho user thường `SERVICE_CHANGE_CONFIG` | `sc sdshow <svc>`; `Get-Acl` trên binary |
| Leo thang bằng token | `SeImpersonate`/`SeDebug`/`SeTakeOwnership` bật cho user thường | `whoami /priv`; Linux `capsh --print`; macOS `sudo -l` |
| MSI elevation | `AlwaysInstallElevated` | `HKLM/HKCU \...\Installer` → `AlwaysInstallElevated` |
| Persistence qua git | Hook / include / insteadOf / credential helper lạ | `git config --global --get-regexp '^(core\.hooksPath\|include\.path\|url\.\|credential\.)'`; `ls .git/hooks \| grep -v sample` |
| Đầu độc package manager | Registry/index URL bị đổi | `.npmrc`, `pip.conf`, `nuget sources`, `go env GOPROXY`, `composer config -g -l` |
| Thoát WSL/Docker lên host | docker.sock, `--privileged`, interop, sudoers | `docker ps --format '{{.Image}}'`; `/etc/sudoers.d`; `~/.wslconfig`; `ls -l /var/run/docker.sock` |
| Extension/host bridge | Native messaging host, `update_url` tự host | `HKCU\Software\Google\Chrome\NativeMessagingHosts`; manifest `update_url` |
| Auto-run task trong workspace | `.vscode/tasks.json` với `runOn: folderOpen` | grep `runOn` trong `.vscode/`; `settings.json` → `terminal.integrated.env` |

### Phase 12 — Secret trong artifact, backup và cloud sync

| Kẻ tấn công dùng để | Kiểm |
|---|---|
| Đọc credential từ IaC | `*.tfstate`, `*.tfplan`, `.terraform/`, `terraform.tfvars`, `*.pem` trong repo |
| Đọc secret từ dump/log | `%LOCALAPPDATA%\CrashDumps`, WER, `*.dmp`, `*.log` chứa `Bearer`/`token=` |
| Đọc bản nháp editor | `*.swp`, `*~`, VS Code `Backups/`, JetBrains `LocalHistory`, Notepad++ backup |
| Đọc output notebook/API tool | `*.ipynb` (outputs), Postman collection + environment, Insomnia export, `*.har` |
| Khôi phục dữ liệu "đã xoá" | Recycle Bin `C:\$Recycle.Bin`; `vssadmin list shadows`; git dangling `git fsck --lost-found`, `git stash list` |
| Lấy secret qua cloud sync | Thư mục đang sync (OneDrive/Drive/Dropbox) có chứa repo/secret: `Get-ChildItem env: \| ? Name -match 'OneDrive\|Drive'`; macOS `~/Library/CloudStorage`; Linux `~/OneDrive`, `rclone config` |
| Đọc memory còn trên đĩa | `pagefile.sys`, `hiberfil.sys` — chỉ nguy hiểm khi ổ chưa mã hoá |

### Phase 13 — Kênh tin cậy & certificate store

| Kẻ tấn công dùng để | Kiểm |
|---|---|
| MITM toàn bộ TLS | Root CA lạ trong máy: `Get-ChildItem Cert:\LocalMachine\Root` (lọc issuer không phải Microsoft/DigiCert/...); macOS `security find-certificate -a -p /Library/Keychains/System.keychain`; Linux `ls /usr/local/share/ca-certificates` |
| Chiếm kênh update | Trạng thái updater (`Get-Service gupdate,GoogleUpdaterService*,edgeupdate`) + quyền ghi trên binary updater; `winget source list`; registry npm/pip override |
| Chặn bằng policy | AppLocker/WDAC có hiệu lực không: `Get-AppLockerPolicy -Effective`; macOS `spctl --status`; Linux SELinux/AppArmor `sestatus`, `aa-status` |

### Phase 14 — Năng lực phát hiện (thứ attacker tắt đầu tiên)

| Kẻ tấn công dùng để | Kiểm |
|---|---|
| Chạy lệnh không để lại dấu | Audit policy: `auditpol /get /category:*`; 4688 + `ProcessCreationIncludeCmdLine_Enabled`; 5140/5145; 4663 |
| Ẩn PowerShell | ScriptBlock (4104), Module, Transcription keys trong `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell` |
| Vô hiệu telemetry | Sysmon/ETW/AMSI provider; `Get-Service Sysmon*`; EDR service DACL (ai stop được) |
| Xoá log | `wevtutil gl Security` (size/retention); event 1102 (log cleared); forwarder **thực sự** nhận log (Splunk/Wazuh agent uptime + queue) |

### Phase 15 — Bề mặt hạ tầng mạng (ngoài listener)

| Kẻ tấn công dùng để | Kiểm |
|---|---|
| PSK Wi-Fi đọc được | `netsh wlan show profiles` (chỉ tên profile) → profile `WPA2-Personal` thì **admin** đọc được PSK (`key=clear` cần quyền cao); **không** thêm tham số in PSK, chỉ ghi "profile X dùng WPA2-Personal ⇒ PSK đọc được bởi admin/malware chạy elevated" |
| Poisoning | LLMNR `EnableMulticast`, NetBIOS `NetbiosOptions`, mDNS responder |
| NTLM leak khi clone repo | File `.lnk/.url/.scf/.library-ms` trong repo (mở ra → gửi hash); `git ls-files '*.[lL][nN][kK]'` |
| Kênh phụ | Print Spooler + Point-and-Print, `WebClient`/WebDAV, `Search-ms` handler |
| Ra ngoài không kiểm soát | Proxy/PAC, DNS, DoH bật/tắt, VPN split tunnel, egress tới host lạ |

### Phase 16 — Vật lý & pre-boot (chỉ cần chạm máy một lần)

`AutoAdminLogon` + `DefaultPassword` · thời gian khoá màn hình (`InactivityTimeoutSecs`) · yêu cầu mật khẩu khi wake · thứ tự boot & USB boot · BIOS/UEFI password · DMA/Thunderbolt protection · hibernation + Fast Startup (memory xuống đĩa) · BitLocker recovery escrow.

### Phase 17 — Bề mặt AI agent / tool tự động (đặc thù máy dev hiện nay)

| Kẻ tấn công dùng để | Kiểm |
|---|---|
| Thực thi binary qua MCP | Mọi entry `command` trong `.mcp.json`/`mcp.json` (đường dẫn có ghi được không), `env` chứa token |
| Persistence qua hook agent | `PreToolUse`/`PostToolUse`/shell hooks trỏ script lạ; `~/.<agent>/settings.json` |
| Bỏ qua phê duyệt | `approvalMode`/`permissions` (yolo/danger-full-access), allow-list cho bash/eval/browser |
| Đọc secret từ transcript | Session DB, `blobs/`, `custom-session-files/`, fact-board — nội dung user dán vào |
| Daemon loopback không auth | CDP (`DevToolsActivePort`), orchestrator/agent daemon cục bộ, MCP HTTP server — bất kỳ process local nào cũng gọi được |
| **Sandbox Escape qua Automation Browser** | Agent dùng Playwright/Puppeteer với Chromium cache lỗi thời + cờ `--no-sandbox` hoặc process IDE/Terminal được cấp quyền Accessibility (macOS TCC / Windows UI Automation) ⇒ GPU/Renderer escape dẫn tới gõ phím giả lập (mở Spotlight/Run, spawn reverse shell) |
| Tự chạy khi login | Agent daemon/PWA autostart |
| Mượn quyền qua AI tool dùng chung | Tool/gateway nội bộ chạy bằng danh tính nào (token của ai, scope, có tách theo user không); nó có đọc được session/credential của người khác không; **log hành động của agent** (ai gọi tool gì) có tồn tại, người đọc lại được, ai xoá được. Nguyên tắc: agent không được có quyền hành động mà con người không đọc lại được log |

### Phase 18 — Chuỗi cung ứng công cụ dev & credential triển khai (đường vào qua người làm ra sản phẩm)

Kẻ tấn công không cần lỗ hổng sản phẩm: nhắm vào máy của kỹ sư — installer bị trộn mã độc, "bài test" tuyển dụng, update channel bị chiếm, token triển khai nằm trên máy cá nhân. Chỉ liệt kê và đếm — không chạy script/installer của artifact nghi ngờ, không in value.

**Độ tin cậy của lệnh**: các mẫu `grep` ở mục [1], [4], [6] đã thử bằng positive + negative control trên GNU grep (Git for Windows). **Chưa** thử trên BSD grep (macOS); các lệnh PowerShell/`brew`/`scoop`/`kubectl`/`pgrep` chưa chạy thử trên cả 3 OS — lệnh lỗi ⇒ ghi "chưa kiểm", không suy diễn "sạch". Kết quả 0 chỉ có nghĩa "sạch" khi positive control cùng kênh trả ≥ 1. Lệnh nằm trong khối code (không escape, chép chạy được). Ghép nhiều mẫu bằng `-e` lặp hoặc `(a|b)` trong `-E`; khớp dấu `|` literal bằng `[|]`. **Không** dùng `\|` trong `grep -E`: đã đo cho kết quả sai (khi thì khớp thừa, khi thì 0 kết quả).

| Kẻ tấn công dùng để | Kiểm |
|---|---|
| [1] Installer/bootstrap bị trojan hoá | Công cụ cài (Homebrew/scoop/choco/nvm/rustup) trỏ đúng upstream; tap/bucket/source lạ; lệnh tải-rồi-chạy-ngay (curl/iwr đẩy thẳng vào sh/iex) trong history; profile shell bị chèn dòng `eval`/`curl`/`base64` |
| [2] "Bài test/assignment" tuyển dụng (repo hoặc archive chạy code) | Artifact tải về 30 ngày gần đây chưa rõ nguồn (Mark-of-the-Web / quarantine); repo mới clone có script tự chạy khi mở/cài: `package.json` (`preinstall`/`install`/`postinstall`/`prepare`), `.devcontainer/devcontainer.json` (`initializeCommand`/`postCreateCommand`), `setup.py`/`pyproject.toml`, `build.rs`, `Makefile`, `.mcp.json` + hook agent trong repo lạ — chỉ đọc, không chạy |
| [3] Token triển khai/production nằm trên máy cá nhân | Credential nào gọi thẳng được deploy/signing/registry của production từ máy này; static hay short-lived; có giới hạn nguồn (IP allow-list, mTLS, workload identity) không. **Câu quyết định mức**: có token + mạng của kẻ tấn công ⇒ gọi được dịch vụ ký/deploy không? Static + không TTL + không giới hạn nguồn ⇒ P0/P1 |
| [4] Service-account key / LLM key bị lộ (LLMjacking) | Key JSON service account và key provider LLM nằm ở đâu, tuổi bao lâu (mtime). Hạn mức/budget/alert phía provider: **chưa kiểm được từ máy trạm** trừ khi user cung cấp — không gọi API provider bằng key tìm được |
| [5] Dán token thô vào trang giả (session hijack, vượt cả password và MFA) | Clipboard history/cloud clipboard/clipboard manager giữ token; file JSON token trong Downloads. Quy tắc: không bao giờ dán JSON chứa `access_token` vào trang web |
| [6] Update channel bị chiếm (agent bảo mật/panel/hosting tự cập nhật bằng quyền root) | Nguồn update có HTTPS + chữ ký không; job định kỳ tải về rồi thực thi; version so với advisory chính thức của vendor (chỉ thấy ở tin tức ⇒ nguyên tắc 10). Đã chạy bản nhiễm ⇒ theo Phase 8, rotate toàn bộ |

```bash
# [1] Installer/bootstrap
git -C "$(brew --repository)" remote get-url origin | sed -E 's#://[^@/]+@#://<redacted>@#'   # phải là https://github.com/Homebrew/brew
brew tap; scoop bucket list; choco source list; winget source list
# CHỈ ĐẾM, không dùng `grep -n` trần (in nguyên dòng, có thể chứa token). <hist> = ~/.zsh_history hoặc ~/.bash_history
grep -cE '(curl|wget)[^|]*[|][[:space:]]*(ba|z)?sh([[:space:]]|$)|iwr[^|]*[|][[:space:]]*iex' <hist>
grep -c -e 'eval' -e 'curl' -e 'base64' ~/.zprofile ~/.bashrc    # đếm theo từng file; xem thêm mtime bằng stat/ls -l

# [2] macOS — artifact gần đây + quarantine
find ~/Downloads -mtime -30 \( -name '*.dmg' -o -name '*.pkg' -o -name '*.command' -o -name '*.zip' \)
xattr -p com.apple.quarantine <file>

# [3] Credential triển khai: chỉ tên/đếm/có-không, KHÔNG in value
kubectl config get-contexts -o name          # đếm context chứa "prod"
# ~/.docker/config.json: chỉ tên khoá `auths` + `credsStore`
# .npmrc, .pypirc, ~/.terraform.d/credentials.tfrc.json, ~/.config/gh/hosts.yml: chỉ có/không + đường dẫn
# ~/.aws/credentials: tên profile + tiền tố key (AKIA = dài hạn, ASIA = tạm); không in key

# [4] Service-account key / LLM key: chỉ tên file (-l)
grep -rIl --include='*.json' '"type": *"service_account"' <dir>
grep -rIlE --include='.env*' '(OPENAI|ANTHROPIC|GEMINI|AZURE_OPENAI|MISTRAL|LITELLM_MASTER)[A-Z_]*KEY' <dir>
# GOOGLE_APPLICATION_CREDENTIALS, application_default_credentials.json: chỉ ghi đường dẫn + mtime

# [5] Clipboard manager đang chạy (macOS/Linux)
pgrep -il 'maccy|raycast|alfred|clipy|copyq|klipper'

# [6] Update channel (Linux) — chỉ liệt kê TÊN FILE (-l): dòng khớp có thể chứa user:pass@ hoặc token
grep -rl -e 'trusted=yes' -e 'allow-insecure' /etc/apt/sources.list /etc/apt/sources.list.d
grep -rl -e '^gpgcheck=0' -e 'sslverify=0' /etc/yum.repos.d
systemctl list-timers
grep -rlE '(curl|wget)[^|]*[|][[:space:]]*(ba|z)?sh([[:space:]]|$)' /etc/cron* /etc/systemd/system
```

```powershell
# [2] Windows — artifact gần đây + Mark-of-the-Web
Get-ChildItem ~\Downloads,~\Desktop -Recurse -Include *.zip,*.iso,*.exe,*.msi,*.ps1,*.lnk,*.jar | Where-Object LastWriteTime -gt (Get-Date).AddDays(-30)
Get-Item <file> -Stream Zone.Identifier       # có stream = đến từ internet

# [5] Clipboard history (lỗi "không tồn tại" = chưa đặt policy/giá trị, không phải lỗi đo)
Get-ItemProperty 'HKCU:\Software\Microsoft\Clipboard' -Name EnableClipboardHistory
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name AllowClipboardHistory,AllowCrossDeviceClipboard

# [6] Chữ ký binary updater
Get-AuthenticodeSignature <updater-binary>
```

**Cách dùng mục này trong report**: ghi rõ mục nào **đã chạy**, mục nào **chưa chạy**. Một danh sách scope không thay thế phép đo — nếu chưa đo thì ghi "chưa kiểm", không ghi "không có".

**Lệnh cần quyền cao (thuộc lượt elevated, đừng chạy ở lượt 1)**: `vssadmin list shadows`, `auditpol /get /category:*`, `sc sdshow <svc>`, `Get-AppLockerPolicy -Effective`, `wevtutil gl <log>`, `Get-CimInstance Win32_Service` khi cần `PathName` đầy đủ của service chạy SYSTEM. Nếu nhận `Access is denied` ⇒ ghi "chưa kiểm (cần elevated)", **không** kết luận "không có shadow copy / không có audit policy".

**Thứ tự chạy đề xuất** (khác thứ tự đánh số, theo blast radius thực tế của một máy dev): **17 → 10 → 12 → 18 → 11 → 14 → 13 → 15 → 16**. Lý do: daemon/agent config sai cho phép thực thi không phê duyệt; `authorized_keys` + credential đã lưu là đường vào không cần password; secret trong artifact/tfstate/dump thường đã rời máy; credential triển khai + chuỗi cung ứng công cụ dev là đường từ máy cá nhân sang production; phần còn lại là persistence và phát hiện.

**Ranh giới**: chỉ liệt kê bề mặt và lệnh kiểm read-only. Không đưa payload, không PoC leo thang, không chạy thử privesc trên máy thật — nếu cần chứng minh, dùng VM cô lập.

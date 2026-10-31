# Local Workstation Security Audit

**Your laptop holds the keys to production. Sixty seconds to find out how wide the door is.**

This is not theoretical. A normal developer machine routinely carries: SSH private keys without a passphrase, a `kubeconfig` for a real cluster, CI/CD tokens, a PAT that can read internal repos, cloud credentials, an unencrypted disk, and three browser profiles that are already logged in. None of that needs a vulnerability to be abused — it only needs **one** of these:

- you clone a random repo and its `.gitmodules` contains a token;
- you install a package and its `postinstall` reads `~/.ssh`;
- you lose the laptop, or somebody boots it from USB;
- an AI agent runs a command in that repo with no approval step.

The largest recent crypto losses all followed this exact path: **one compromised endpoint → valid credentials on it → the live system**. The 2022 LastPass incident is the cleanest verifiable example: the attacker went after a DevOps engineer's personal machine, then reached the vault.

This repo is an executable checklist for that endpoint check — on Windows, macOS and Linux.

---

## Install in 60 seconds

**Fastest way (Recommended — auto-detects all agents/CLIs):**
```bash
npx skills add duhd/local-workstation-security-audit -g -y
```
*The command above automatically installs the skill into the universal `~/.agents/skills/` directory and symlinks it for Claude Code, Codex, Amp, Antigravity, Cline, OpenCode, +17 more.*

---

Or choose manual instructions matching your tool of choice:

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

`omp` and `pi` auto-discover skills placed under the agent home directory:
```bash
# Windows PowerShell:
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.omp\agent\skills" | Out-Null
git clone https://github.com/duhd/local-workstation-security-audit "$env:USERPROFILE\.omp\agent\skills\local-workstation-security-audit"

# macOS / Linux:
mkdir -p "$HOME/.omp/agent/skills"
git clone https://github.com/duhd/local-workstation-security-audit "$HOME/.omp/agent/skills/local-workstation-security-audit"
```
Restart your session or run `/skill:local-workstation-security-audit`.

### 3. OpenAI Codex CLI

Clone to your local instructions or Codex skills directory:
```bash
git clone --depth 1 https://github.com/duhd/local-workstation-security-audit "$HOME/.codex/skills/local-workstation-security-audit"
```
Then run in Codex:
```bash
codex "Perform a local security audit following instructions in ~/.codex/skills/local-workstation-security-audit/SKILL.md"
```

### 4. Cursor / Windsurf / VS Code (Agent Mode)

Add the rule to your project:
```bash
mkdir -p .cursor/rules   # For Cursor
cp "$HOME/.claude/skills/local-workstation-security-audit/SKILL.md" .cursor/rules/security-audit.mdc
```
In Cursor/Windsurf Agent chat, type `@security-audit.mdc run a local security audit for this workstation`.

### 5. Claude Desktop (GUI)

Claude Desktop lacks a built-in shell out of the box. Two ways to run:
1. **Automated (Recommended)**: Add a Terminal MCP Server (such as `@wonderwhy-er/desktop-commander` or any shell MCP) to your `claude_desktop_config.json`. Then paste [`PROMPT.md`](PROMPT.md) into the chat.
2. **Assisted (Human-in-the-loop)**: Paste [`PROMPT.md`](PROMPT.md) directly into chat. Claude will craft the exact PowerShell/Bash commands for each Phase for you to run and paste back.

### 6. Any other AI Agent harness (Generic)

Open [`PROMPT.md`](PROMPT.md), copy everything, and paste it into any agent with shell execution capabilities.


Requirement to run the audit: the agent must have a shell tool (Bash / PowerShell / terminal). Without a shell it must stop and ask you to paste command output — it must **not** describe the checklist as if it had been checked.

**Automated Update Check**: The Skill and Prompt natively check for newer versions on GitHub at the start of every audit run. If a newer release is detected, the Agent will pause and prompt you before updating.

**Manual Update**:
- **If installed via `npx skills`**:
  ```bash
  # Use the installed skill name (local-workstation-security-audit):
  npx skills update local-workstation-security-audit -g -y
  ```
- **If installed via `git clone`**:

```bash
git -C "$HOME/.claude/skills/local-workstation-security-audit" pull --ff-only
# the command file is a COPY, not a symlink — re-copy it after every pull
cp "$HOME/.claude/skills/local-workstation-security-audit/commands/local-pc-security-audit.md" \
   "$HOME/.claude/commands/"
```

On Windows PowerShell:

```powershell
git -C "$env:USERPROFILE\.claude\skills\local-workstation-security-audit" pull --ff-only
Copy-Item "$env:USERPROFILE\.claude\skills\local-workstation-security-audit\commands\local-pc-security-audit.md" `
  "$env:USERPROFILE\.claude\commands\" -Force
```

After copying, restart the harness (or reload skills) so the command appears.

> **For an agent reading this:** next step is `SKILL.md` — run Phase 1 → 9 (posture), then Phase 10 → 17 (attacker-first). A complete pass is **all 17 phases**; never run only half. With ~30 minutes, do **Phase 1 (patch/disk encryption), 3 (network exposure), 5 (browser)** first, then **17 → 10 → 12** — that set surfaces the heaviest findings on a dev machine. Read-only by default. Never print secrets. Ask the user to choose an option per finding before changing anything on the machine.

---

## What this repo contains

| File | Role |
|---|---|
| `README.md` | Vietnamese introduction |
| `README.en.md` | English introduction (this file) |
| `SKILL.md` | The full skill — evidence rules, 3-OS command matrix, severity anchors, remediation playbooks, the "traps that bit" table, and **Phase 10–17** (attacker-first) |
| `PROMPT.md` | Prompt to paste into any agent, no skill loader needed |
| `commands/local-pc-security-audit.md` | Slash-command entry point |
| `.gitattributes` | LF normalisation so it works on macOS/Linux |

---

## What it checks

**Phase 1–9 — posture.** OS patch level (via update searcher, not a KB list) · disk encryption · TPM/Secure Boot/SIP · firewall + listeners + overlay-network ACL · credentials at rest · persistence · browser profiles, extensions, remote-access hosts · repos and git history · **application patch gap + CVE mapping** (NVD/MSRC/EPSS, high-risk subset only: browser, remote-access host, OS component, VPN, file parsers) · severity · remediation · report.

**Phase 10–17 — attacker-first.** The part usually missed, because it appears in no CIS checklist. Four questions it answers:

- **Who can still log into this machine?** — `authorized_keys`, Credential Manager/Keychain, shell history, `AutoAdminLogon`, LSA protection.
- **How would someone else's code run?** — PATH hijack, service path/DACL, `SeImpersonate`, git hooks, package-manager registry, WSL/docker, extension `update_url`.
- **Where do secrets live after "deletion"?** — tfstate, crash dumps, editor backups, notebook output, shadow copies, `git fsck`, cloud-synced folders.
- **What can still be detected, and which channels bypass listeners?** — audit policy, PowerShell 4104, Sysmon/AMSI, forwarder health; Wi-Fi PSK, LLMNR/NetBIOS, `.lnk/.scf` files in repos, spooler/WebDAV.

The full 8-phase breakdown with 3-OS commands lives in the *attacker-first* section of [`SKILL.md`](SKILL.md) — that is the only copy to update when a phase is added.

### Proactive Workstation Hardening (OS-Customized)

Beyond reactive remediation of discovered vulnerabilities, the skill provides a **Proactive Hardening Baseline** tailored for each operating system:
- **Windows**: RunAsPPL (LSASS Mimikatz defense), Credential Guard, disable LLMNR/NetBIOS broadcast, disable Fast Startup RAM dumps, Defender ASR rules, UAC credential prompt strictness, and PATH reordering.
- **macOS**: Enforce SIP & Gatekeeper, Application Firewall Stealth mode, destroy FileVault keys from RAM on standby (`destroyfvkeyonstandby`), disable Remote Login/VNC, and sudo timeout restrictions.
- **Linux**: Restrict ptrace scope (`kernel.yama.ptrace_scope = 2`), disable core dumps (`limits.conf`), UFW Default Deny, Docker socket isolation (keep user out of `docker` group), and SSH daemon hardening.
- **AI Agent & Dev Tooling**: Pin MCP server versions, prohibit `auto-accept` on untrusted repos, and isolate credentials outside permanent shell profiles.
---

## Five principles that make this different from a checklist

1. **Read-only by default.** Nothing changes on the machine until you pick an option per finding.
2. **Never print secrets.** Name, length, path only. Any command that can emit a value (`git remote -v`, `git config --get-regexp 'remote.*'`, `manage-bde -status`) must be redacted inside the pipeline.
3. **Every measurement carries a positive control.** "Not found" usually means "searched wrong", not "does not exist" — narrow filters create false negatives, and a false negative in security is worse than not knowing.
4. **Three states, not two.** *Checked and clean* / *checked and broken* / **could not check**. `Access denied` belongs to the third.
5. **Verify by state, not exit code** — and **re-measure after fixing**: stopping a service may not close the port; a deny ACE only applies to handles opened afterwards; a provisioner can recreate a disabled account; `UsedSpaceOnly` reports 100% while free space stays plaintext.

Remediation order when several layers are involved: **revoke credentials → tighten permissions/ACLs → rewrite history / disable services**. Doing it the other way (edit files first, forget the revoke) is the most common mistake.

---

## Output

A report at `docs/security/<YYYY-MM-DD>-local-workstation-security-audit.md`:

1. Metadata — host, OS, privileges, scope.
2. Findings table **ranked by blast radius** (P0 → P3) with the *observed impact*.
3. Each finding with all four parts: **Evidence / Fix / Verify / Rollback**.
4. Remediation status: applied · attempted and rolled back · pending.
5. Rejected conclusions — so the next run does not repeat them.
6. Coverage limits — what was not checked, and why.

The report contains IPs, hostnames and internal paths ⇒ **treat it as internal**, never commit it to a public repo.

### Post-Audit Interactive Triage Prompt

Once the audit is completed and the report is generated, **do not manually guess fixes or let the agent blindly mutate your system**. Paste this prompt to have the agent interview you finding-by-finding:

```markdown
"Based on the completed audit report, act as a senior system security engineer and walk me through each finding one-by-one (from P0, P1 down to P3). For each finding, provide:
1. An Accept option (explaining the accepted risk and operational consequences).
2. Concrete Fix options (minimal vs. complete, including exact commands to run and any breaking side effects).
Only execute the chosen remediation after I explicitly confirm my choice."
```

---

## Limits & ethics

This repo describes **surfaces and read-only checks only**. No payloads, no exploits, no privilege-escalation PoCs. If you need to prove an escalation path, do it on an isolated VM — never on a real machine.

One rule always holds: **a scope list is not a measurement.** Anything not measured must be recorded as "not checked", never as "none".

---

## Version & releases

- Current version: see [`VERSION`](VERSION) — SemVer.
- Change history: [`CHANGELOG.md`](CHANGELOG.md).
- Each release is a `vX.Y.Z` git tag plus a GitHub Release carrying the same changelog.

Release process (manual, no CI required):

```bash
# 1) make changes, update CHANGELOG.md and VERSION
git commit -am "feat: <what changed>"
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main --tags
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file CHANGELOG.md
```

## License

No license granted. Internal use; contact the author before reuse or redistribution. If you want it fully open, add a `LICENSE` file (MIT / Apache-2.0 / CC-BY-4.0) — that decision belongs to the repo owner.

## Notes

This skill was distilled from a real audit in which several early conclusions had to be corrected because of false negatives: narrow filters missed `Port=Any` firewall rules, `ls -la` on Windows reported wrong ACLs, tool output redaction destroyed evidence, stopping a service did not close a port held by the kernel driver, and `Enable-BitLocker` printed the recovery password to the console. The **"Traps that actually bit"** table in `SKILL.md` is the most valuable part — read it first.

Vietnamese version: [`README.md`](README.md)

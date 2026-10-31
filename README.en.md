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

**Option 1 — harness with a skill loader** (macOS / Linux / Git Bash):

```bash
mkdir -p "$HOME/.claude/skills"
git clone https://github.com/duhd/local-workstation-security-audit \
  "$HOME/.claude/skills/local-workstation-security-audit"
# verify, then run:
test -f "$HOME/.claude/skills/local-workstation-security-audit/SKILL.md" && echo OK
/local-pc-security-audit
```

**Option 1b — Windows PowerShell:**

```powershell
git clone https://github.com/duhd/local-workstation-security-audit `
  "$env:USERPROFILE\.claude\skills\local-workstation-security-audit"
Test-Path "$env:USERPROFILE\.claude\skills\local-workstation-security-audit\SKILL.md"
```

> Replace `.claude/skills` with your harness's skill directory — that layout is only an example. If your harness has no concept of a skill directory, use Option 2.

**Option 2 — no skill loader:** open `PROMPT.md` and paste the whole thing into your agent.

**The only requirement:** the agent must have a shell tool (Bash / PowerShell / terminal). Without a shell it must stop and ask you to paste command output — it must **not** describe the checklist as if it had been checked.

> **For an agent reading this:** next step is `SKILL.md` — run Phase 1 → 9 (posture), then Phase 10 → 17 (attacker-first). Read-only by default. Never print secrets. If you only have time for one pass, follow the priority order in `SKILL.md` (**17 → 10 → 12 → 11 → 14 → 13 → 15 → 16**). Ask the user to choose an option per finding before changing anything on the machine.

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

**Phase 1–9 — posture.** OS patch level (via update searcher, not a KB list) · disk encryption · TPM/Secure Boot/SIP · firewall + listeners + overlay-network ACL · credentials at rest · persistence · browser profiles, extensions, remote-access hosts · repos and git history · application patch gap · severity · remediation · report.

**Phase 10–17 — attacker-first.** The part usually missed, because it appears in no CIS checklist:

| Phase | The one question |
|---|---|
| 10 | **Who can still log into this machine?** `authorized_keys`, Credential Manager/Keychain, shell history, `AutoAdminLogon`, LSA protection |
| 11 | **How would someone else's code run?** PATH hijack, service paths, service DACLs, `SeImpersonate`, `AlwaysInstallElevated`, git hooks, package-manager registry, WSL/docker, extension `update_url` |
| 12 | **Where do secrets live after "deletion"?** tfstate, crash dumps, editor backups, notebook output, Postman exports, Recycle Bin, shadow copies, `git fsck` |
| 13 | **Is a trust channel compromised?** rogue root CAs, updaters, `winget source` |
| 14 | **What can still be detected?** audit policy, PowerShell 4104, Sysmon/AMSI, log retention, whether forwarders actually receive logs |
| 15 | **Which channels bypass listeners?** Wi-Fi PSK, LLMNR/NetBIOS, `.lnk/.scf` files in repos (NTLM hash leak), spooler/WebDAV |
| 16 | **What if someone touches the machine?** auto-login, screen lock, boot order, BIOS password, hibernation |
| 17 | **What is the AI-agent surface?** `.mcp.json` `command`, agent hooks, `approvalMode`, transcripts, unauthenticated loopback daemons |

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

---

## Limits & ethics

This repo describes **surfaces and read-only checks only**. No payloads, no exploits, no privilege-escalation PoCs. If you need to prove an escalation path, do it on an isolated VM — never on a real machine.

One rule always holds: **a scope list is not a measurement.** Anything not measured must be recorded as "not checked", never as "none".

---

## License

No license granted. Internal use; contact the author before reuse or redistribution. If you want it fully open, add a `LICENSE` file (MIT / Apache-2.0 / CC-BY-4.0) — that decision belongs to the repo owner.

## Notes

This skill was distilled from a real audit in which several early conclusions had to be corrected because of false negatives: narrow filters missed `Port=Any` firewall rules, `ls -la` on Windows reported wrong ACLs, tool output redaction destroyed evidence, stopping a service did not close a port held by the kernel driver, and `Enable-BitLocker` printed the recovery password to the console. The **"Traps that actually bit"** table in `SKILL.md` is the most valuable part — read it first.

Vietnamese version: [`README.md`](README.md)

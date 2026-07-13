# Non-AD vulnerabilities — roadmap & pending work

PurpleForge started as an Active-Directory-only lab harness. This document tracks
the extension to **OS-level** and **application** vulnerabilities so any later
session can pick it up without re-deriving the design.

Status legend: ✅ done · 🟡 partial · ⬜ pending.

---

## Tier A — OS-level local privilege escalation (Windows)

**✅ Landed (branch `agentic-system`, 2026-07-09).**

Five catalog vulns + Ansible inject task-files, each planting a LocalSystem/SYSTEM
privesc primitive on a workstation with an Authenticated-Users-writable gap:

| id | ATT&CK | primitive |
|----|--------|-----------|
| `unquoted-service-path` | T1574.009 | LocalSystem service, unquoted space-bearing `ImagePath`, writable prefix `C:\PFApps` |
| `weak-service-permissions` | T1574.011 | LocalSystem service whose DACL grants `SERVICE_ALL_ACCESS` to Authenticated Users |
| `dll-hijacking` | T1574.001 | LocalSystem service whose own binary directory is writable (DLL search-order #1) |
| `scheduled-task-privesc` | T1053.005 | Scheduled task as SYSTEM running an Authenticated-Users-writable script |
| `always-install-elevated` | T1548.002 | `AlwaysInstallElevated=1` in HKLM + HKCU |

**Targeting mechanism (the structural change).** New catalog field
`attack.target_role` (`workstation` | `member-server` | `domain-controller`).
Resolution precedence in `scripts/forge.py:plan_vuln_injection`:
`requires_services` → `target_role` → default root DC. `semantic_checks` errors if
the spec has no machine of the declared role. AD vulns are unchanged (no
`target_role` ⇒ still land on the root DC).

Files:
- `catalog/vulnerabilities/{unquoted-service-path,weak-service-permissions,dll-hijacking,scheduled-task-privesc,always-install-elevated}.yml`
- `templates/ansible/vulns/<same ids>.yml`
- `scripts/forge.py` — `plan_vuln_injection` (target_role branch), `semantic_checks`
  (target_role validation), `VULN_CREDENTIAL_NOTES` (report rows).

Verified end-to-end: `lab-spec` OK, `guardrail` PASS (invariant #2), all five plays
target the workstation (not the DC), task-files copied to `generated/`, negative
test (no workstation ⇒ clear semantic error).

### ✅ WinRM local validation — DONE (2026-07-10)

`WINRM_APPLIED_CHECKS` in `scripts/forge.py` (`run_live_validation`) now
auto-confirms `applied` for all 5 OS vulns plus writable-gpo/adminsdholder-acl,
via `nxc winrm <ip> -X "<PowerShell>"` one-liners that each print a
`PF_CHECK:True/False` marker. `exploitable` stays `REQUIRES-HUMAN` by design
(actually exploiting is a state-changing manual step, same as
`LDAP_APPLIED_FILTERS`). Full writeup + the two real bugs this surfaced (a
deploy-blocking wrong Ansible collection on `scheduled-task-privesc`, and a
check-script regex that didn't account for `sc.exe sdshow`'s symbolic SDDL
rendering) is in the `winrm-live-validation` memory entry.

### ✅ Deploy smoke test — DONE (2026-07-10)

Stood up `winrm-validate-lab` (`specs/winrm-validate-lab.yml`, DC + 1
workstation) with all 5 OS vulns + writable-gpo/adminsdholder-acl. Deployed,
validated (7/7 auto-confirmed applied=YES after fixing the two bugs above),
destroyed to cost-zero. First-ever live run of the 5 Tier A vulns. Kept as a
committed regression-test spec for re-running this smoke test later.

### ⬜ Pending to close Tier A

1. **Real hardening reconciliation.** `neutralized_by` uses free-label controls
   (placeholder pattern), so `defensive-controls` records only a baseline-level
   conflict, never a concrete `skip_rule`. Two of them map to REAL CIS items and
   should be wired into `catalog/defense/hardening/control-cis-rules.yml`:
   - `always-install-elevated` → CIS "Always install with elevated privileges =
     Disabled" (Computer + User config).
   - `dll-hijacking` → CIS SafeDllSearchMode.
   The service-ACL / unquoted-path / scheduled-task controls have no direct CIS
   rule; leave them as free-label (documented in each vuln's NOTE comment).

---

## Tier B — Application vulnerabilities on Windows

### ✅ MSSQL: xp_cmdshell + weak sa — DONE (2026-07-13)

First Tier B vuln landed and smoke-tested live end-to-end. New pieces:

- **service-provisioning phase** (`templates/ansible/playbooks/service-provisioning.yml.j2`,
  wired into `site.yml` between `ad-topology` and `ad-population` —
  `scripts/forge.py`'s `plan_service_provisioning`/`render_service_provisioning`):
  installs a machine's declared `services` SECURELY, before any vuln lands.
  Only `mssql` is wired; `iis`/`sccm` remain declared-but-unconsumed.
- **`templates/ansible/services/mssql-install.yml`**: wraps
  `vendor/GOAD/ansible/roles/mssql`'s install mechanics (unattended config +
  installer download/run), trimmed to a SECURE base install — sa disabled,
  Windows-auth only, xp_cmdshell off. `ADDCURRENTUSERASSQLADMIN=True` makes
  the domain admin a sysadmin login, reused by vuln inject tasks via
  `SqlCmd -E`.
- **`catalog/vulnerabilities/mssql-weak-sa.yml`** + `templates/ansible/vulns/mssql-weak-sa.yml`
  (T1505.001): enables sa (weak password) + Mixed Mode auth + xp_cmdshell on
  top of the secure baseline — `requires_services: [mssql]` routes it to the
  right member-server, the existing targeting mechanism.
- **Live validation**: `nxc mssql <ip> -u sa -p <pass> --local-auth -x whoami`
  proves both applied AND exploitable in one shot (same pattern as
  `ROAST_FLAGS`) — wired into `run_live_validation`/`_live_command`.

**Three real bugs found and fixed during the first-ever live deploy:**
1. `{{ domain }}` is DC-only in the inventory (member-servers only carry
   `member_domain`), and `domain_username` is already NETBIOS-qualified
   (`CORP\Administrator`) — my `SQLYSADMIN` var was doubly wrong. Fixed to
   just `{{ domain_username }}`.
2. The SSEI bootstrap installer failed silently at
   "Downloading install package..." — confirmed live that `SchUseStrongCrypto`
   was unset in both .NET Framework registry hives, a well-documented cause
   for exactly this symptom on fresh Windows images. Fixed by setting it
   before running the installer.
3. **The real connectivity bug**: SQL Server installed and listened on 1433
   fine, but was unreachable from off-box. Confirmed live: the member-server's
   NIC stayed `NetworkCategory: Public` well after domain-join (a known Azure
   NLA-misclassification quirk), so the firewall rule's `Profile: "Domain"`
   never applied to real traffic (`win_wait_for`'s own port check passed
   because it's a loopback check, masking this). Fixed by opening the rule on
   `Domain, Private, Public` — isolation is enforced at the NSG layer
   (deny-by-default, management-subnet-only), not the guest firewall, so this
   doesn't weaken anything.

Smoke-tested on `mssql-weak-sa-lab` (`specs/mssql-weak-sa-lab.yml`, kept as a
regression-test spec): deployed, validated (1/1 applied=YES exploitable=YES),
destroyed to cost-zero.

### ⬜ Still pending in Tier B

- IIS: a deliberately vulnerable web app (deployment artifact required) — no
  provisioning phase exists for it yet (only `mssql` is wired).
- `neutralized_by` for mssql-weak-sa is a free-label placeholder (no matching
  ansible-lockdown CIS rule — SQL Server hardening isn't a Windows-OS CIS/STIG
  surface ansible-lockdown covers).
- No linked-server / cross-database privesc chain yet — this first vuln is
  the single-hop sa/xp_cmdshell primitive only.

---

## Tier C — Application vulnerabilities on Linux

**⬜ Pending, largest.** Requires:
- Linux entries in the machine `os` enum (`specs/schema/lab-spec.schema.json`) —
  today Windows-only.
- Infra/Ansible outside GOAD's reuse (GOAD is Windows/AD).
- A Linux hardening baseline (ansible-lockdown has CIS-Linux roles — reusable).
- A distinct validation path (SSH, not WinRM).
Effectively a new lab class; do Tier A validation + Tier B first.

---

## Design invariants that still apply

- Every non-AD vuln MUST still ship `detect` + `mitigate` + `neutralized_by` +
  valid `mitre_attack` (invariant #2). The `guardrail` gate enforces this.
- OS/app vulns land on an already-hardened box (deploy order unchanged): hardening
  baseline → vuln injection → EDR → clean snapshot.
- Injection stays deterministic and idempotent (invariant #5).

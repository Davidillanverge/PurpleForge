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

### ⬜ Pending to close Tier A

1. **WinRM local validation (highest priority).** `purple-validation` /
   `purple-validator` is `nxc`/LDAP-only today — it cannot confirm these OS vulns.
   Each catalog entry carries a `validate.local_check` hint; a WinRM-based local
   validator needs to be added that, per vuln, checks over the tunnel:
   - `unquoted-service-path`: `Win32_Service.PathName` unquoted + contains a space,
     and the prefix dir ACL is writable by Authenticated Users.
   - `weak-service-permissions`: `sc.exe sdshow <svc>` contains a wide `;AU)` ACE.
   - `dll-hijacking`: service binary dir ACL writable by Authenticated Users + runs
     as LocalSystem.
   - `scheduled-task-privesc`: task runs as SYSTEM and its script is writable by
     Authenticated Users.
   - `always-install-elevated`: both HKLM and HKCU `AlwaysInstallElevated == 1`.
   This is a new validation path parallel to the AD one in `scripts/forge.py`
   (search `nxc`/`netexec` around the validate command) and in
   `.claude/skills/purple-validation/SKILL.md`.

2. **Real hardening reconciliation.** `neutralized_by` uses free-label controls
   (placeholder pattern), so `defensive-controls` records only a baseline-level
   conflict, never a concrete `skip_rule`. Two of them map to REAL CIS items and
   should be wired into `catalog/defense/hardening/control-cis-rules.yml`:
   - `always-install-elevated` → CIS "Always install with elevated privileges =
     Disabled" (Computer + User config).
   - `dll-hijacking` → CIS SafeDllSearchMode.
   The service-ACL / unquoted-path / scheduled-task controls have no direct CIS
   rule; leave them as free-label (documented in each vuln's NOTE comment).

3. **Deploy smoke test.** None of the five has been through a live deploy +
   validate yet. Stand up a small lab with a workstation and at least
   `always-install-elevated` (purely registry, lowest risk) to confirm the runas
   become path works on a non-DC host, then the service-based ones.

---

## Tier B — Application vulnerabilities on Windows

**⬜ Pending.** Bigger lift: the `services` enum (`iis`/`mssql`/`sccm`) is declared
in the machine schema but **only `adcs` is actually provisioned** — nothing consumes
`iis`/`mssql`/`sccm` today (verified: no consumer in `scripts/` or `templates/`).

Concrete work:
- Wire provisioning for a service (start with MSSQL): install + configure the stack
  in an Ansible role, the way `adcs` is provisioned for `adcs-esc1`.
- Author app vulns that reuse the `requires_services` targeting that already exists:
  - MSSQL: `xp_cmdshell` enabled / weak `sa` / linked-server privesc (half-AD, a
    well-known lab pattern, good first target).
  - IIS: a deliberately vulnerable web app (deployment artifact required).
- `neutralized_by` maps cleanly to app-hardening / CIS where available.

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

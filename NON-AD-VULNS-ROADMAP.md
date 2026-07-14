# Non-AD vulnerabilities — roadmap & pending work

Tracks extending PurpleForge from AD-only to **OS-level** and **application**
vulns. Status: ✅ done · 🟡 partial · ⬜ pending.

## Tier A — OS-level local privilege escalation (Windows) ✅

Landed (branch `agentic-system`, 2026-07-09). Five catalog vulns + inject
task-files, each planting a SYSTEM privesc primitive on a workstation with an
Authenticated-Users-writable gap:

| id | ATT&CK | primitive |
|----|--------|-----------|
| `unquoted-service-path` | T1574.009 | LocalSystem service, unquoted space-bearing `ImagePath`, writable prefix `C:\PFApps` |
| `weak-service-permissions` | T1574.011 | service DACL grants `SERVICE_ALL_ACCESS` to Authenticated Users |
| `dll-hijacking` | T1574.001 | service whose own binary directory is writable |
| `scheduled-task-privesc` | T1053.005 | SYSTEM task running an Authenticated-Users-writable script |
| `always-install-elevated` | T1548.002 | `AlwaysInstallElevated=1` in HKLM + HKCU |

**Targeting mechanism:** new catalog field `attack.target_role` (`workstation` |
`member-server` | `domain-controller`). Precedence in `plan_vuln_injection`:
`requires_services` → `target_role` → default root DC. `semantic_checks` errors if
no machine of the declared role exists. AD vulns unchanged (no `target_role` ⇒ root
DC). Files: `catalog/vulnerabilities/<5 ids>.yml`, `templates/ansible/vulns/<5
ids>.yml`, `scripts/forge.py`.

**✅ WinRM local validation (2026-07-10):** `WINRM_APPLIED_CHECKS` auto-confirms
`applied` for all 5 (plus writable-gpo/adminsdholder-acl) via `nxc winrm <ip> -X`
one-liners printing `PF_CHECK:True/False`. `exploitable` stays `REQUIRES-HUMAN` by
design (state-changing). See `winrm-live-validation` memory.

**✅ Deploy smoke test (2026-07-10):** `winrm-validate-lab` (DC + 1 workstation),
deployed → validated (7/7 applied=YES) → destroyed cost-zero. Kept as a
regression-test spec.

**✅ Hardening reconciliation (2026-07-13), Tier A closed:**
`disable_always_install_elevated` and `safe_dll_search_mode` map to VERIFIED
ansible-lockdown rules in `control-cis-rules.yml` (all 5 relevant OSes):
- `always-install-elevated`: Computer (18.10.81.2 server / 18.10.80.2 Win10/11) +
  User (19.7.44.1 / 19.7.42.1), CIS L1.
- `dll-hijacking`: SafeDllSearchMode=1 (18.5.8 / 18.5.9), CIS L1. **Caveat (in the
  catalog entry):** SafeDllSearchMode only moves %CWD% later in the search order,
  NOT step 1 (the loading module's dir, where this vuln plants its DLL) — the
  control is real but does NOT neutralize THIS primitive; the real fix is the ACL
  change in `mitigate.summary`.

Fixed a pre-existing bug while wiring this: `resolve_hardening_skip_rules` only
consulted `control-cis-rules.yml` for `kind: "control"` conflicts, skipping
`kind: "baseline"` (the free-label + `hardening.baseline` pattern EVERY OS-privesc
vuln uses) — so a free-label control could never resolve a concrete skip_rule. Now
it keys off `c.get("control")` regardless of `kind`. See `tier-a-cis-mapping`
memory. Service-ACL / unquoted-path / scheduled-task have no direct CIS rule —
permanently free-label (documented per vuln), a correct state, not a gap.

## Tier B — Application vulnerabilities on Windows

**✅ MSSQL: xp_cmdshell + weak sa (2026-07-13)** — first Tier B vuln, smoke-tested
live:
- **Service-provisioning phase** (`service-provisioning.yml.j2`, wired into
  `site.yml` between `ad-topology` and `ad-population`;
  `plan_service_provisioning`/`render_service_provisioning`) installs a machine's
  declared `services` SECURELY before any vuln. Only `mssql` is wired
  (`iis`/`sccm` declared-but-unconsumed).
- **`mssql-install.yml`** wraps GOAD's `mssql` role, trimmed to a secure base (sa
  disabled, Windows-auth only, xp_cmdshell off; `ADDCURRENTUSERASSQLADMIN=True`).
- **`mssql-weak-sa`** (T1505.001) enables sa (weak password) + Mixed Mode +
  xp_cmdshell on top; `requires_services: [mssql]` routes it to the member-server.
- **Validation:** `nxc mssql <ip> -u sa -p <pass> --local-auth -x whoami` proves
  applied AND exploitable in one shot.

Three bugs fixed on the first live deploy:
1. `{{ domain }}` is DC-only in the inventory; `domain_username` is already
   NETBIOS-qualified → used `{{ domain_username }}` directly.
2. SSEI installer failed silently at download — `SchUseStrongCrypto` unset in both
   .NET registry hives; set it before running the installer.
3. SQL listened on 1433 but unreachable off-box: the member-server NIC stayed
   `NetworkCategory: Public` after domain-join (Azure NLA quirk), so a
   `Profile: "Domain"` rule never applied. Fixed by opening on `Domain, Private,
   Public` — isolation is enforced at the NSG (deny-by-default), not the guest
   firewall, so this doesn't weaken anything.

Smoke-tested on `mssql-weak-sa-lab` (kept as regression spec): 1/1 applied=YES
exploitable=YES, destroyed cost-zero.

**⬜ Still pending in Tier B:**
- IIS: a deliberately vulnerable web app (no provisioning phase yet — only mssql).
- `mssql-weak-sa`'s `neutralized_by` is a free-label placeholder (SQL Server
  hardening isn't a Windows-OS CIS/STIG surface ansible-lockdown covers).
- No linked-server / cross-database privesc chain (single-hop sa/xp_cmdshell only).

## Tier C — Application vulnerabilities on Linux ⬜

Largest, pending. Needs: Linux entries in the machine `os` enum (Windows-only
today); infra/Ansible outside GOAD's reuse; a Linux hardening baseline
(ansible-lockdown has CIS-Linux roles); a distinct validation path (SSH, not
WinRM). Effectively a new lab class — do Tier A + B first.

## Design invariants that still apply

- Every non-AD vuln still ships `detect` + `mitigate` + `neutralized_by` + valid
  `mitre_attack` (invariant #2; `guardrail` enforces).
- OS/app vulns land on an already-hardened box (deploy order unchanged).
- Injection stays deterministic + idempotent (invariant #5).

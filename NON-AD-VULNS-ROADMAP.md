# Non-AD vulnerabilities — roadmap & pending work

Tracks extending PurpleForge from AD-only to **OS-level** and **application**
vulns. Status: ✅ done · 🟡 partial · ⬜ pending.

## Sequenced delivery plan (agreed 2026-10-02)

Agreed phase order for the current round. Separates **services** (the
platform/daemon that runs — IIS, MSSQL, SCCM) from **applications** (what gets
deployed on top and carries its own flaws). Telemetry (SWG/EDR/SIEM) is
**deferred** this round — it would reverse invariant #2 (adds the DETECT pillar);
recorded as a proposal only, no implementation planned here. See **Telemetry
(DETECT pillar)** below for the stack/provider details.

- **Phase 1 — Services: install + VALIDATE they work (no vulns yet).** Each
  `machines[].services` entry installs SECURELY and passes an "is up" check
  before any gap is injected. MSSQL is the proven template. **Starting with IIS**
  (secure web server baseline); SCCM stays declared-but-unconsumed unless pulled
  in. Hooks: `plan_service_provisioning` (planning.py), `render_service_provisioning`
  (render.py), `service-provisioning.yml.j2`, `templates/ansible/services/<svc>-install.yml`.
- **Phase 2 — Vulns, two fronts in parallel.**
  - *2A · service-backed:* IIS misconfig (WebDAV/PUT/app-pool→potato), MSSQL
    linked-server chain, lax SMB shares. Reuse service-provisioning: secure base →
    inject reopens the gap (same pattern as `mssql-weak-sa`).
  - *2B · no service needed (starts immediately):* new AD/ADCS (ESC2/3/8, SID
    history, LDAP anon bind…), misconfig (SYSVOL creds, insecure DNS updates, OU
    ACLs…), OS privesc (`SeImpersonate`→potato, stored creds, COM hijacking…).
    Reuses the existing `attack.target_role` + task-file + reconciliation pattern.
- **Phase 3 — Applications with associated vulns.** App(s) deployed on IIS that
  carry their own flaws (SQLi web→DB→RCE against the MSSQL host, unvalidated
  upload, auth bypass). Decision pending: own toggleable app (recommended) vs.
  vendored vulnerable app; adds an **HTTP** validation path to `validate.py`.
  See **Application catalog** below for the third-party apps to provision (then
  build vulns/CVEs on, same model as services).
- **Phase 4 — Later: CVEs + Linux.**
  - *CVEs:* needs an image/patch-level decision first — a patch-level CVE can't
    survive a fully-patched+hardened box, which fights hardening-before-vulns.
    Schema impact: `attack.cve` + version/patch pin; content guardrail (no
    wormable/destructive without guards).
  - *Tier C Linux:* new lab class — Linux in the `os` enum, infra beyond GOAD's
    reuse, CIS-Linux baseline, SSH validation path. Largest track, done last.

Every vuln across all phases still ships `mitigate` + `neutralized_by` + valid
`mitre_attack`, no `detect` block (invariant #2), lands on an already-hardened
box, and injects deterministically + idempotently (invariant #5).

## Application catalog — third-party apps to provision (then build vulns on) ⬜

Pending. These are **applications** (full products), not Windows services. They
follow the same contract as `services:` — **install the app SECURELY in a
provisioning phase, then catalog vulns/CVEs reopen specific gaps on top**
(`requires_services`/`requires_apps` routing, reconciliation-aware,
deterministic). None are implemented yet; this is the backlog + the shape of the
enabling work.

**Enabling work (prerequisite for all of them):** an **application-provisioning
phase** parallel to `service-provisioning` — a new `machines[].applications: []`
field + enum, a `plan/render_application_provisioning`, one
`templates/ansible/apps/<app>-install.yml` per app (secure baseline + an "is up"
check, exactly like `iis`/`ftp`/`mssql`), and `requires_apps` on catalog vulns.
This is the richer sibling of the "one self-contained app per vuln" model used in
Phase 3 so far, and the right home for multi-flaw products.

| App | Platform / stack | Install approach | Best home | Representative vuln/CVE class | Effort |
|---|---|---|---|---|---|
| **Jenkins** | Java (JRE) — cross-platform | MSI/WAR + Windows service | Windows (Phase 3) | Script-Console RCE, unauth access, CVE-2024-23897 (arg-file read) | low–med |
| **Jira** | Java + DB (bundled/ext) — Win or Linux | Atlassian installer + DB | Windows (Phase 3) or Linux | SSTI CVE-2019-11581, auth bypass CVE-2022-0540, path traversal | high (DB, heavy) |
| **Microsoft SharePoint** | Windows + IIS + SQL Server (farm) | Farm install, reuses iis+mssql services | Windows (Phase 3) | CVE-2019-0604, "ToolShell" CVE-2025-53770/53771 | very high |
| **WordPress** | PHP + MySQL/MariaDB | IIS+PHP (Win) or LAMP (Linux) | Linux (Tier C) or IIS | plugin/theme RCE, XML-RPC abuse, weak-admin, SQLi | med (needs PHP+DB) |
| **Joomla** | PHP + MySQL/MariaDB | IIS+PHP (Win) or LAMP (Linux) | Linux (Tier C) or IIS | unauth info disclosure CVE-2023-23752, SQLi, weak-admin | med (needs PHP+DB) |
| **GitLab** | Linux (Omnibus CE) | omnibus package | **Linux (Tier C)** | CVE-2021-22205 (ExifTool RCE), account-takeover CVEs | high, Linux |
| **KeePass** | Windows desktop (not a server) | a planted `.kdbx` + key material | artifact, any Windows host | crackable/weak master, key-file alongside DB, CVE-2023-32784 (master pw from memory) | low (different model) |

Notes:
- **KeePass is not a provisioned service/server** — it is a credential-store
  artifact. Model it like `sysvol-script-creds`: plant a `.kdbx` (+ maybe its key
  file) on a host for the attacker to exfiltrate and crack. No provisioning phase
  needed; it is a vuln, not an app to install.
- **WordPress/Joomla/GitLab are PHP/Linux-leaning** → they pull the
  application-provisioning work toward **Tier C Linux** (PHP+DB or Omnibus, SSH
  validation). WordPress/Joomla *can* run on Windows via IIS+PHP if a
  Windows-only lab is wanted first.
- **Jenkins is the best starting point**: cross-platform Java, trivial Windows
  service install, and a famously rich offensive surface — highest value/effort
  ratio of the set, and it validates the application-provisioning phase before the
  heavier products (Jira/SharePoint) or the Linux pivot.
- Every app vuln still obeys invariant #2 (mitigate + neutralized_by + valid
  mitre_attack, no detect). CVE-based entries additionally depend on the Phase-4
  image/patch-level decision.

## Telemetry (DETECT pillar) — deferred ⬜

Deferred by decision (2026-10-02). This is a **scope reversal, not an extension**:
PurpleForge today is PREVENT/RESPOND only, and DETECT is designed OUT —
`CLAUDE.md` invariant #2, the vuln schema hard-forbids `detect`/`siem_rule`
(`false`), the `defense.edr[].product` enum accepts only `defender-av`, and the
skills say "don't add SIEM". Recorded here as the intended shape for when/if that
decision is revisited; no implementation is planned in the current rounds.

### Three layers (deploy the tools)

Telemetry splits into three independent layers, each a pluggable **provider** so a
lab picks one per layer (mirrors how `defense.edr[]` already abstracts a product):

| Layer | Priority example | Alternatives | What it is |
|---|---|---|---|
| **SWG** (Secure Web Gateway) | **Cloudflare** (Gateway / WARP) | **Zscaler** (ZIA) | egress/web filtering + web telemetry from the lab hosts |
| **EDR** (endpoint agent) | **Elastic Agent / Elastic Defend** | **MDE** (Microsoft Defender for Endpoint) | endpoint detection agent beyond the built-in Defender-AV |
| **SIEM** (detection backend) | **Elastic SIEM** (Elastic Security) | **Microsoft Sentinel** | log/telemetry aggregation + detection rules |

Priority stack: **Cloudflare + Elastic Agent + Elastic SIEM**. Each provider needs
a **backend/tenant** this project deliberately does not build today (a console,
API keys, an agent enrollment token) — so adding any is new infra + new secret
handling, and tenant-bound config tensions with the account-independence
invariant (secrets would no longer be purely seed-derived).

### Connect to the tools (obtain results)

The point of the stack is a **detection-coverage feedback loop**: after
`/validate` fires each injected attack, pull the detections/alerts back from each
provider's API and correlate them to the vuln that triggered them — turning the
current applied+exploitable matrix into an applied+exploitable+**detected**
matrix. Integration points per provider:

- **Elastic SIEM** — Elastic Detections/Alerts API (query alerts by time window +
  rule).
- **MDE** — the Defender/Graph security API (`alerts`/`incidents`).
- **Sentinel** — Log Analytics query API (KQL over the workspace).
- **Cloudflare / Zscaler** — Gateway/ZIA logs API for the web-egress events.

### Enabling work (the scope reversal)

- Rewrite invariant #2 to admit DETECT (PREVENT/RESPOND → PREVENT/RESPOND/DETECT).
- Relax the vuln schema's `detect: false` / `siem_rule: false` guard and add an
  optional detection-expectation block per vuln.
- Expand `defense.edr[].product` beyond `defender-av`; add a `telemetry:` block
  (SWG/EDR/SIEM provider + backend credentials) to the lab spec + schema.
- A new deploy phase (agent enrollment + SWG/SIEM wiring) and a results-pull step
  in `validate.py`; backend credential handling outside the seed-derived model.

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
ids>.yml`, `scripts/forge/`.

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

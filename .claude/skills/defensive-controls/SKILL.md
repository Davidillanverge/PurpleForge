---
name: defensive-controls
description: >
  Applies the resolved defense.hardening baseline (via the pinned
  vendor/ansible-lockdown Windows-*-CIS/-STIG roles, with skip_rules derived
  from the reconciliation), the fixed hardening.controls.* toggles (LAPS, LSA
  protection, SMB/LDAP signing, LLMNR/NBT-NS/mDNS, Credential Guard,
  Protected Users — pf_controls, PurpleForge-authored), EDR (defender-av
  only — every other product needs a backend this project does not build,
  no detection-lab), and deception (honey accounts). This is where the
  hardening<->vuln reconciliation becomes a real ansible-lockdown skip_rule,
  not just a manifest entry.
---

# defensive-controls

## When to use this skill

- During `/generate`, after `vuln-injection`, to render
  `generated/<lab>/ansible/playbooks/defensive-controls.yml`.
- During `/deploy`, in the CLAUDE.md order: `... → hardening baseline →
  vuln-injection → EDR/telemetry → snapshot`. In practice the generated
  playbook applies hardening → EDR → pf_controls → deception, in that order
  within itself (see the playbook's own play order).
- No detection-lab (SIEM/Sysmon/WEF) exists in this project by design — this
  skill is PREVENT/RESPOND only, not VER. Don't add SIEM plumbing here.

## The honesty model (read this before touching `neutralized_by`)

A vuln's `neutralized_by` entry is only as good as the ansible-lockdown rule
it claims to correspond to. Fase 6 audited every seed vuln against the
pinned `vendor/ansible-lockdown/Windows-2019-CIS`/`Windows-2022-CIS` roles and
found:

- **Verified, concrete mappings** (in
  `catalog/defense/hardening/control-cis-rules.yml`): `smb_signing` → CIS
  rules 2.3.8.1/2.3.8.2/2.3.9.2/2.3.9.3 (level 1, identical on both server
  OSes — the clean demonstrable case, see `smb-signing-disabled` vuln),
  `ldap_signing` → 2.3.5.3/2.3.5.4/2.3.11.8-or-9 (the client-side rule number
  genuinely differs between 2019 and 2022), `disable_llmnr_nbtns_mdns` →
  18.6.4.1/18.6.4.2, `lsa_protection` → 18.9.26.2 (RunAsPPL) — **but that rule
  is tagged `ngws-*`, not `level1`/`level2`, so it is NOT applied by a default
  cis-l1/cis-l2 baseline at all**. An earlier draft of `unconstrained-
  delegation.yml` claimed `hardening.baseline: [cis-l2, stig]` neutralized it
  — that was checked against the actual role and found false, and removed
  (see the vuln file's own comment).
- **Unverified/conceptual labels**: `adcs_template_hardening`,
  `gpp_cpassword_removed`, `preauth_required_audit`,
  `service_account_password_policy`, `acl_hygiene_audit`,
  `ad_object_description_audit` — no matching CIS rule exists in the
  benchmark for these (verified by grep across the pinned roles' task files;
  see each vuln's own comment). The reconciliation still treats them as
  baseline conflicts for `warn`/`exclude-control` purposes (lab-spec doesn't
  need the rule number to know a *conceptual* conflict exists), but
  `resolve_hardening_skip_rules` in `scripts/forge.py` cannot derive a
  concrete `skip_rule` for them — it says so explicitly in the manifest's
  `hardening_plan.notes` and in `forge.py generate`'s console output, rather
  than silently doing nothing or guessing a rule number.
- **STIG is entirely unmapped**: STIG roles gate on per-STIG-ID vars
  (`wn22_ac_000020`), not the CIS roles' `winXXcis_rule_N_N_N` scheme, and use
  `cat1`/`cat2`/`cat3` severity tags instead of `level1`/`level2`. No STIG
  skip_rule mapping has been verified — `hardening.baseline: stig` always
  produces an honest note instead of a skip_rule.

**When adding a vuln or a control, verify the claim against the actual pinned
role** (`grep` the rule text in `vendor/ansible-lockdown/Windows-*-CIS/tasks/`)
before writing a `neutralized_by` entry — don't assume a plausible-sounding
control name maps to something real.

## How CIS level selection actually works (and why it matters here)

`vendor/ansible-lockdown/Windows-2022-CIS/README.md` states level selection
"is managed using tags" (`level1-domaincontroller`, `level2-memberserver`,
etc.) — **selected via `--tags`/`--skip-tags` at `ansible-playbook` invocation
time**, not a bulk profile variable. DC vs. member-server applicability is
handled separately, automatically, by the role's own `prelim.yml` runtime
fact-detection (`ansible_windows_domain_role` → `prelim_winXXcis_is_domain_controller`)
— so the *level* tags (`level1`/`level2`) are what this project's baseline
selection actually needs to pass, uniformly across all hosts in a play,
regardless of whether each host is a DC or a member server.

Consequence: **the tags on the generated playbook's `include_role` are
necessary but not sufficient** — a real `/deploy` must also invoke
`ansible-playbook` with a matching `--tags` (e.g. `--tags
level1-domaincontroller,level1-memberserver` for `cis-l1`).
`forge.py generate`'s console output and `lab-manifest.json.hardening_plan`
both carry this information; a future `/deploy` orchestrator should pass it
through. Windows-10/11-CIS roles use a different, bare tag scheme
(`level1`/`level2`, no `-domaincontroller`/`-memberserver` suffix) — this is a
real structural difference between role generations, not an oversight (see
`catalog/defense/hardening/cis-l1.yml`'s `tags_by_role.workstation`).

## LAPS: authored, not GOAD's role

`vendor/GOAD/ansible/roles/laps/*` is deeply coupled to GOAD's own data model
(`lab.hosts[dict_key].domain`, `lab.domains[domain].laps_path`, custom
`win_gpo_*`/`win_ad_dacl` library modules) and was not reused — forcing it
onto PurpleForge's different inventory model would cost more than it saves.
`pf_controls` instead enables native **Windows LAPS** (built into Windows
Server 2019+/Windows 10 22H2+, no external module): one-time
`Update-LapsADSchema` on the primary root DC, then a registry policy
(`HKLM:\Software\Microsoft\Policies\LAPS`) on every target host.

## EDR: only `defender-av` is real

`catalog/defense/edr/defender-av.yml` is the only entry with
`backend_required: false` — Microsoft Defender Antivirus is built into every
Windows image, no console to stand up. `pf_defender_av` implements ASR rules
(mode-driven: `prevent`→block, `detect`/default→audit, overridable via
`settings.asr_rules`), tamper protection, network protection, and real-time
protection. Every other product (`elastic-defend`, `wazuh-agent`, `mde`,
`velociraptor`, `limacharlie`) needs a management backend this project does
not build — `plan_edr` in `scripts/forge.py` marks them
`status: not-implemented` with an explicit reason, and `forge.py generate`
prints that reason. **Don't silently skip an EDR selection** — if you add a
product, either implement it host-only or mark it `backend_required: true`.

## Testing this skill (four real bugs were caught here, not by inspection)

No live DC in CI. Validate structurally, but validate for real — these four
were only caught by actually running the tools:

1. **`ansible.cfg`'s `roles_path` didn't include `vendor/ansible-lockdown`.**
   `--syntax-check` doesn't resolve `include_role` (it's dynamic), so this
   passed syntax-check while being unable to find `Windows-2019-CIS` at
   runtime. Caught by statically `import_role`-ing every role
   (ansible-lockdown + all three `pf_*`) from a throwaway playbook — only
   `import_role` resolves at parse time and fails loudly if the role isn't
   found:
   ```bash
   ANSIBLE_CONFIG=generated/<lab>/ansible/ansible.cfg ansible-playbook --syntax-check /tmp/check.yml
   # /tmp/check.yml: one import_role task per role name, tags: ['never']
   ```
2. **A string containing a literal backslash (`KINGDOM\da-treasury`, from
   `hardening.controls.protected_users_group`) rendered into a double-quoted
   YAML scalar broke the parse** (`\d` isn't a legal YAML escape). Caught by
   actually `yaml.safe_load`-ing the generated file, not just eyeballing it.
   Fixed by routing every free-form string through `scripts/forge.py:yaml_scalar`
   (`json.dumps`-based quoting) instead of raw `"{{ v }}"` interpolation.
3. **Empty Python lists rendered as nothing after a YAML `key:`** parse as
   `None`, not `[]` — `pf_controls_protected_users_group | length` then
   raises at Ansible runtime (not caught by `--syntax-check`, which doesn't
   evaluate `when:`). Fixed with an explicit `{% if %}...{% else %} []{% endif %}`
   around every list-valued var in `defensive-controls.yml.j2` and
   `hosts.yml.j2`. Caught by generating the `defense.profile: none` case
   (empty hardening/EDR/protected-users) and `yaml.safe_load`-ing it, not just
   the vuln-rich medieval example.
4. **`pf_defender_av`'s tamper-protection registry write
   (`HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection`)
   always fails with "Requested registry access is not allowed" on a real,
   standalone (non-Intune-managed) VM.** Microsoft ACL-locked this specific
   key to the Defender platform itself starting Windows 10 1903, precisely so
   local admins/malware can't disable tamper protection via script — there is
   no supported non-Intune API to set it (`Set-MpPreference` has no
   tamper-protection parameter either, by the same design). This can't be
   fixed by trying harder; it's a real platform limitation. Changed the task
   to `register` + `failed_when: false` with a follow-up debug task
   reporting whether it actually applied, instead of hard-failing the whole
   `site.yml` run over a control that was never enforceable on this kind of
   VM — same honesty model as the EDR-backend and unverified-`neutralized_by`
   cases above, not a silent skip.

```bash
python3 scripts/forge.py generate specs/examples/medieval-2dom-azure.yml
python3 -c "import yaml; yaml.safe_load(open('generated/shadow-keep/ansible/playbooks/defensive-controls.yml'))"
cd generated/shadow-keep/ansible && ansible-playbook --syntax-check -i inventory/hosts.yml playbooks/defensive-controls.yml
```

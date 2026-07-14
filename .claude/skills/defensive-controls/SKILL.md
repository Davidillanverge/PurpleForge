---
name: defensive-controls
description: >
  Applies the resolved defense.hardening baseline (via pinned
  vendor/ansible-lockdown Windows-*-CIS/-STIG roles with skip_rules from the
  reconciliation), the fixed hardening.controls.* toggles (LAPS, LSA protection,
  SMB/LDAP signing, LLMNR/NBT-NS/mDNS, Credential Guard, Protected Users —
  pf_controls), EDR (defender-av only), and deception (honey accounts). This is
  where the reconciliation becomes a real ansible-lockdown skip_rule.
---

# defensive-controls

## When to use

- `/generate`, after `vuln-injection`, to render `defensive-controls.yml`.
- `/deploy`, in the CLAUDE.md order (`... → hardening → vuln-injection → EDR →
  snapshot`). The playbook itself runs hardening → EDR → pf_controls → deception.
- No detection pipeline exists by design — PREVENT/RESPOND only. Don't add SIEM.

## The honesty model (read before touching `neutralized_by`)

A `neutralized_by` entry is only as good as the ansible-lockdown rule it maps to.
Audited against pinned `Windows-2019-CIS`/`Windows-2022-CIS`:

- **Verified mappings** (`catalog/defense/hardening/control-cis-rules.yml`):
  `smb_signing` → 2.3.8.1/2.3.8.2/2.3.9.2/2.3.9.3 (L1, identical both OSes);
  `ldap_signing` → 2.3.5.3/2.3.5.4/2.3.11.8-or-9 (client-side number differs
  2019 vs 2022); `disable_llmnr_nbtns_mdns` → 18.6.4.1/18.6.4.2; `lsa_protection`
  → 18.9.26.2 (RunAsPPL) — **but that rule is tagged `ngws-*`, NOT
  `level1`/`level2`, so a default cis-l1/l2 baseline never applies it.** (An
  earlier `unconstrained-delegation.yml` claim of `[cis-l2, stig]` was checked,
  found false, removed.)
- **Unverified/conceptual labels** (`adcs_template_hardening`,
  `gpp_cpassword_removed`, `preauth_required_audit`,
  `service_account_password_policy`, `acl_hygiene_audit`,
  `ad_object_description_audit`): no matching CIS rule exists (verified by grep).
  Reconciliation still treats them as baseline conflicts for warn/exclude, but
  `resolve_hardening_skip_rules` can't derive a concrete `skip_rule` — it says so
  in `hardening_plan.notes` and console output, never guesses.
- **STIG is entirely unmapped**: STIG roles gate on per-ID vars (`wn22_ac_000020`)
  with `cat1/2/3` tags, not `winXXcis_rule_N_N_N`/`level1`. `baseline: stig`
  always produces an honest note, no skip_rule.

**When adding a vuln/control, verify the claim against the actual role** (`grep`
the rule text in `vendor/ansible-lockdown/Windows-*-CIS/tasks/`) before writing a
`neutralized_by` — don't assume a plausible name maps to something real.

## CIS level selection

ansible-lockdown selects levels via **`--tags`/`--skip-tags` at `ansible-playbook`
invocation time** (`level1-domaincontroller`, `level2-memberserver`, …), not a
profile var. DC-vs-member applicability is handled automatically by the role's
`prelim.yml` fact-detection, so only the *level* tags need passing, uniformly.
**Consequence: the `include_role` tags in the playbook are necessary but not
sufficient** — a real `/deploy` must also pass `--tags`
(e.g. `level1-domaincontroller,level1-memberserver` for cis-l1).
`hardening_plan` carries this; a `/deploy` orchestrator should pass it through.
Windows-10/11-CIS use a bare `level1`/`level2` scheme (no `-domaincontroller`
suffix) — a real generation difference, see `cis-l1.yml`'s `tags_by_role.workstation`.

## LAPS: authored, not GOAD's role

GOAD's `laps` role is coupled to GOAD's data model + custom modules — not reused.
`pf_controls` enables native **Windows LAPS** (Server 2019+/Win 10 22H2+, no
external module): one-time `Update-LapsADSchema` on the primary root DC, then a
registry policy (`HKLM:\Software\Microsoft\Policies\LAPS`) on every target.

## EDR: only `defender-av`

`catalog/defense/edr/defender-av.yml` is the only entry with `backend_required:
false` (built into every Windows image, no console). `pf_defender_av` does ASR
rules (mode-driven: `prevent`→block, `detect`/default→audit, overridable via
`settings.asr_rules`), tamper/network/real-time protection. It's the only value
`defense.edr[].product` accepts. Any other EDR needs a backend this project
doesn't build; `plan_edr` marks a stray product `status: not-implemented` with a
reason. **Don't silently skip an EDR selection** — implement it host-only, or
mark `backend_required: true`.

## Testing (structural — four real bugs, only caught by running the tools)

1. **`ansible.cfg` `roles_path` missing `vendor/ansible-lockdown`** — `--syntax-
   check` doesn't resolve dynamic `include_role`, so it passed while unable to
   find `Windows-2019-CIS`. Catch by `import_role`-ing every role from a throwaway
   playbook (`import_role` resolves at parse time):
   ```bash
   ANSIBLE_CONFIG=generated/<lab>/ansible/ansible.cfg ansible-playbook --syntax-check /tmp/check.yml
   ```
2. **Literal backslash (`KINGDOM\da-treasury` from `protected_users_group`) in a
   double-quoted YAML scalar breaks the parse.** Fixed by routing every free-form
   string through `forge.py:yaml_scalar` (json.dumps quoting).
3. **Empty Python lists render as nothing → parse as `None`, not `[]`** →
   `... | length` raises at runtime. Fixed with `{% if %}...{% else %} []{% endif
   %}` around every list-valued var. Catch by generating `defense.profile: none`
   and `yaml.safe_load`-ing it.
4. **`pf_defender_av` tamper-protection registry write always fails** ("Requested
   registry access is not allowed") on a non-Intune VM — Microsoft ACL-locked
   that key since Win10 1903; no supported non-Intune API. Not fixable; changed to
   `register` + `failed_when: false` + a debug report, same honesty model. Every
   other Defender control is unaffected.

```bash
python3 scripts/forge.py generate specs/<lab>.yml
python3 -c "import yaml; yaml.safe_load(open('generated/<lab>/ansible/playbooks/defensive-controls.yml'))"
cd generated/<lab>/ansible && ansible-playbook --syntax-check -i inventory/hosts.yml playbooks/defensive-controls.yml
```

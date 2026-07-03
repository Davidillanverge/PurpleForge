---
name: vuln-injection
description: >
  Turns the spec's vulnerabilities[] into an Ansible playbook that injects each
  selected, catalog-defined weakness as a NAMED, deterministic, idempotent
  artifact, targeting the right host (adcs-* on the ADCS member-server,
  domain-level vulns on the primary domain's root DC). Records the intended
  attack path and the reconciliation-derived neutralization status per vuln in
  lab-manifest.json. Runs after ad-theming and (at deploy time) after the
  hardening baseline — the intentional gaps land in an already-hardened box.
---

# vuln-injection

## When to use this skill

- During `/generate`, after `ad-theming`, to render
  `generated/<lab>/ansible/playbooks/vuln-injection.yml`,
  `generated/<lab>/ansible/vulns/<id>.yml`, and (if `adcs-esc1` is selected)
  the copied ADCS support files.
- During `/deploy`, in the CLAUDE.md order: `... → hardening baseline →
  vuln-injection → EDR/telemetry → snapshot`. Vulns are injected *after*
  hardening so they are genuine, deliberate gaps in an otherwise-hardened
  environment — the most realistic scenario.

## Reuse vs. author, and why the injected artifacts are NAMED, not random

The catalog (`catalog/vulnerabilities/<id>.yml`) is the source of truth for
what each vuln is; this skill turns it into runnable Ansible. Where a mature
primitive exists it's reused, but **Vulnerable-AD's own functions are NOT
called directly**: `VulnAD-Kerberoasting`/`VulnAD-ASREPRoasting`/
`VulnAD-PwdInObjectDescription` pick a *random existing user* each run, which
violates PurpleForge invariant #5 (determinism, seed-driven) and isn't
idempotent (invariant: idempotent playbooks). So this skill reuses their
*techniques* on **named, deterministic artifacts** created via the same
standard modules GOAD uses (`win_domain_user` with `spn`,
`Set-ADAccountControl -DoesNotRequirePreAuth`, etc.).

| Vuln | Upstream reused | How |
|---|---|---|
| `adcs-esc1` | **GOAD `adcs_templates` role** (directly) | forge.py copies GOAD's ADCSTemplate PS module + ready-made `ESC1.json` into `ansible/playbooks/files/adcs/`; the task installs *only* the ESC1 template (not GOAD's full ESC1–6 sweep) |
| `kerberoasting` | Vulnerable-AD technique | `win_domain_user` creates `svc-sqlreport` with an `MSSQLSvc/...` SPN + a dictionary-crackable password |
| `asreproast` | Vulnerable-AD technique | `win_domain_user` creates `svc-legacyapp`, then `Set-ADAccountControl -DoesNotRequirePreAuth $true` |
| `passwords-in-description` | Vulnerable-AD technique | `win_domain_user` creates `temp-contractor` with its real password echoed into the description |
| `dcsync-acl` | GOAD `acls` technique, **extended** | GOAD's acls role only maps force-change-password/self-membership GUIDs; this adds the two DS-Replication-Get-Changes[-All] GUIDs mimikatz needs |
| `unconstrained-delegation` | none (authored) | `Set-ADComputer -TrustedForDelegation $true` on the target member server, following the VulnAD-* module style |
| `gpp-cpassword` | none (authored) | creates a real GPO and drops a `Groups.xml` with the published-key `cpassword` (decrypts to `Local*8!`) into its SYSVOL Preferences path |

The weak passwords for the roastable accounts (`Password123!`,
`Summer2024!`) are intentionally dictionary-crackable — that IS the vuln —
and are non-secret by design; they live only in gitignored `generated/<lab>/`.
Accounts whose weakness isn't the password itself (`dcsync-acl`,
`passwords-in-description`) get a strong random password from
`generate_password()`.

## Host targeting (`plan_vuln_injection` in scripts/forge.py)

- A vuln whose catalog `attack.requires_services` is non-empty runs on the
  host that provides that service — `adcs-esc1` (`requires_services: [adcs]`)
  runs on the ADCS member-server, where the ADCSTemplate module and the CA
  live. `lab-spec`'s semantic checks already guaranteed such a host exists,
  so the lookup can't fail here.
- Every other vuln is domain-level and runs on the **primary domain's root
  DC** (first non-child domain, first DC — `groups["domain_controllers"][0]`).
  There is no per-vuln domain targeting in the schema today; a multi-domain
  spec injects domain-level vulns into the primary domain only. If a lab needs
  a vuln in a specific child domain, that's a future schema addition, not
  something to hardcode here.
- `unconstrained-delegation` is domain-level (the play runs on the DC, which
  has rights to modify any computer object) but its *affected* object is the
  first member server — passed as `vuln_unconstrained_computer`.

## Respecting the reconciliation (the Purple-team point)

vuln-injection does **not** re-run the reconciliation — it reads the result
`lab-spec` already computed in `lab-manifest.json` and annotates each planned
vuln with a `neutralization` status:

- **`gap-preserved`** — the vuln's neutralizing control was excluded
  (`on_conflict: exclude-control` + `intentional_gaps_auto`), so the injected
  gap stays open in the hardened box. This is the intended, most-valuable
  outcome.
- **`AT RISK`** — a neutralizing hardening control is applied and was *not*
  excluded (`on_conflict: warn`), so this gap may be closed by the baseline.
  The vuln is still injected, but `/validate` may later report it PREVENTED.
- **`clear`** — no selected hardening control neutralizes this vuln at all.

(`on_conflict: fail` never reaches this skill — `lab-spec` aborts generation
first.) The concrete `skip_rule` exclusions that make `gap-preserved` real on
the box are applied later by `defensive-controls`; this skill only relies on
their having been decided.

## Adding a vuln

Add `catalog/vulnerabilities/<id>.yml` (with `detect`/`mitigate`/
`neutralized_by`/`mitre_attack` — enforced by review, see CLAUDE.md) and a
`templates/ansible/vulns/<id>.yml` task-file. If it needs deterministic
per-vuln vars (account/computer names), extend `build_vuln_vars` in
`scripts/forge.py`; if it targets a service host, give it
`attack.requires_services`. No other generator changes are required.

## Testing this skill

No live DC in CI. Validate structurally:

```bash
python3 scripts/forge.py generate specs/examples/medieval-2dom-azure.yml
cd generated/shadow-keep/ansible
ansible-playbook --syntax-check -i inventory/hosts.yml playbooks/vuln-injection.yml
```

`--syntax-check` does not descend into `include_tasks`, so to validate the
task-files themselves, statically `import_tasks` them from a throwaway
playbook and syntax-check that (this is how Phase 4 verified all seven).
Confirm `lab-manifest.json.vulnerabilities_planned` lists each vuln with its
`run_on` host and `neutralization` status.

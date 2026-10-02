---
name: vuln-injection
description: >
  Turns the spec's vulnerabilities[] into an Ansible playbook that injects each
  catalog-defined weakness as a NAMED, deterministic, idempotent artifact,
  targeting the right host (adcs-* on the ADCS member-server, domain-level vulns
  on the primary root DC). Records the intended attack path and the
  reconciliation-derived neutralization status per vuln in lab-manifest.json.
  Runs after ad-theming and (at deploy time) after hardening — gaps land in an
  already-hardened box.
---

# vuln-injection

## When to use

- `/generate`, after `ad-theming`, to render `vuln-injection.yml`, `vulns/<id>.yml`,
  and (if `adcs-esc1` selected) the copied ADCS support files.
- `/deploy`, after hardening (gaps land in an otherwise-hardened box).

## Named, not random (reuse vs author)

The catalog is the source of truth; this skill turns it into runnable Ansible.
**Vulnerable-AD's own functions are NOT called** —
`VulnAD-Kerberoasting`/`-ASREPRoasting`/`-PwdInObjectDescription` pick a random
existing user each run, violating invariant #5 (determinism) and idempotency. So
their *techniques* are reused on **named, deterministic artifacts** built with the
standard modules GOAD uses.

| Vuln | Upstream | How |
|---|---|---|
| `adcs-esc1` | GOAD `adcs_templates` role | copies GOAD's ADCSTemplate module + `ESC1.json`; installs ONLY the ESC1 template |
| `kerberoasting` | Vulnerable-AD technique | `win_domain_user` `svc-sqlreport` + `MSSQLSvc/...` SPN + crackable password |
| `asreproast` | Vulnerable-AD technique | `svc-legacyapp` + `Set-ADAccountControl -DoesNotRequirePreAuth $true` |
| `passwords-in-description` | Vulnerable-AD technique | `temp-contractor` with its real password in the description |
| `dcsync-acl` | GOAD `acls`, **extended** | adds the two DS-Replication-Get-Changes[-All] GUIDs mimikatz needs |
| `unconstrained-delegation` | authored | `Set-ADComputer -TrustedForDelegation $true` on the target member server |
| `gpp-cpassword` | authored | real GPO + `Groups.xml` with the published-key `cpassword` (decrypts to `Local*8!`) in SYSVOL |

Weak passwords for roastable accounts (`Password123!`, `Summer2024!`) are
intentionally crackable — that IS the vuln — and non-secret (gitignored
generated/ only). Accounts whose weakness isn't the password (`dcsync-acl`,
`passwords-in-description`) get a strong random `generate_password()`.

## Host targeting (`plan_vuln_injection`)

- A vuln with non-empty `attack.requires_services` runs on the host providing it
  (`adcs-esc1` → the ADCS member-server). `lab-spec` already guaranteed it exists.
- Every other vuln is domain-level → the **primary domain's root DC**
  (`groups["domain_controllers"][0]`). No per-vuln domain targeting in the schema;
  multi-domain injects domain-level vulns into the primary domain only.
- `unconstrained-delegation` is domain-level (runs on the DC) but its *affected*
  object is the first member server (`vuln_unconstrained_computer`).

## Respecting the reconciliation (the Purple point)

Doesn't re-run reconciliation — reads `lab-spec`'s result from
`lab-manifest.json` and tags each vuln:

- **`gap-preserved`** — neutralizing control was excluded, gap stays open in the
  hardened box. The intended, most-valuable outcome.
- **`AT RISK`** — a neutralizing control is applied and NOT excluded
  (`on_conflict: warn`); still injected, but `/validate` may report PREVENTED.
- **`clear`** — no selected control neutralizes it.

(`on_conflict: fail` never reaches here — `lab-spec` aborts first.) The concrete
`skip_rule` exclusions are applied later by `defensive-controls`.

## Adding a vuln

1. **`catalog/vulnerabilities/<id>.yml`** — `detect`/`mitigate`/`neutralized_by`/
   `mitre_attack` enforced by review. `neutralized_by` must be checked against the
   actual pinned role (see the notes in `kerberoasting.yml`/
   `constrained-delegation.yml`); if no real rule neutralizes it, say so rather
   than inventing a label `defensive-controls` can't turn into a `skip_rule`.
2. **`templates/ansible/vulns/<id>.yml`** — the injection task-file. Reuse an
   upstream technique where one exists; the artifact must be named and
   deterministic (`svc-<x>`, not a random user) for idempotency. Password:
   crackable if the weak password IS the vuln, random `generate_password()` else.
3. **Deterministic per-vuln vars** (names): extend `build_vuln_vars`.
   **Service-host targeting**: give it `attack.requires_services` (lab-spec
   validates the host).

Before "done" — every item below was a real bug caught only against a live domain:

- **Kerberos-ticket vulns**: set `msDS-SupportedEncryptionTypes = 28`
  (RC4+AES128+AES256) explicitly via `Set-ADUser -Replace` (see
  `kerberoasting.yml`). **Unset no longer means "RC4-crackable"** — on a
  fully-patched 2016 deploy, EVERY principal got `KDC_ERR_ETYPE_NOSUPP` for every
  ticket request (Microsoft RC4 deprecation).
- **Any var that can hold a literal backslash** (`DOMAIN\user`): route through
  `yaml_scalar()`, not raw `"{{ var }}"`. An unescaped `\` in a double-quoted YAML
  scalar is a hard parse failure that broke every lab's inventory (shared
  template). See `ad-topology`.
- **`--syntax-check` doesn't descend into `include_tasks`** — won't catch a broken
  task-file. See Testing.
- **Test the exploit for real.** `site.yml` completing proves the AD objects
  exist, NOT that they're exploitable (the encryption-types bug is the example:
  account existed, right SPN/flags, Ansible reported success, still uncrackable).
  Run the actual attack (`nxc`/Impacket per the catalog's `validate`).
- **A schema/attribute-name typo in a `-Filter`/guard fails silently as
  "unchanged", not as an error.** `laps-read-acl` guarded on
  `lDAPDisplayName -eq "ms-LAPS-Password"` (real name: `msLAPS-Password`, no
  hyphen) — every run reported `ok`, vuln silently never applied. Verify a schema
  name against `Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext` on a
  real DC, not from memory.

## Testing (structural — no live DC)

```bash
forge generate specs/<lab>.yml
cd generated/<lab>/ansible
ansible-playbook --syntax-check -i inventory/hosts.yml playbooks/vuln-injection.yml
```

`--syntax-check` doesn't descend into `include_tasks` — to validate task-files,
`import_tasks` them from a throwaway playbook and syntax-check that. Confirm
`vulnerabilities_planned` lists each vuln with its `run_on` host + `neutralization`
status. **None of this replaces a live-domain exploit test** (see the last
checklist item).

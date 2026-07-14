---
name: ad-theming
description: >
  Deterministically generates each domain's entire AD population (OU tree, users,
  groups, computers, memberships, ACL noise) in Python (scripts/population.py),
  themed from lab.theme and seeded from population.seed — no BadBlood involved.
  Runs after ad-topology (domains/trusts must exist), before vuln-injection,
  which casts population objects into vulnerability roles.
---

# ad-theming

## When to use

- `/generate`, right after `ad-topology`'s inventory/playbook, to compute the
  population plan and render `ad-population.yml`.
- `/deploy`, after AD topology is up, before vuln injection (deploy order:
  `infra → ad-topology → ad-population → hardening → vulns → EDR → snapshot`).

## Not BadBlood anymore

Earlier versions wrapped `vendor/BadBlood` unmodified. Its randomness only
happens on the live Windows host at Ansible-runtime, so `forge.py` could never
know usernames/passwords/OU placement ahead of a deploy. Replaced by
`scripts/population.py` — a **deliberate, user-confirmed departure from the
"wrap upstream" principle, scoped only to BadBlood**. GOAD/Vulnerable-AD/
ansible-lockdown are still wrapped; `vendor/BadBlood` stays pinned but unused.

## How it works

`population.py`'s `generate_population_plan()` is a pure function seeded with one
`random.Random(population.seed + offset)`. It reproduces BadBlood's actual
ratios/naming (read from BadBlood's PowerShell source) — the goal is to MATCH its
realism, not exceed it: 3%/97% service/person split, flat-random OU placement,
25%/75% admin-group/distlist naming, 80% group-membership participation, etc. The
one deliberate change: **every user's password is generated and recorded** (the
whole point — document the full domain, passwords included, before deploy).

`render_ad_population()` (`forge.py`) calls it once per populatable domain (root
+ child DCs, per-domain seed offset), then renders `ad-population.yml.j2` — one
play per domain that APPLIES the precomputed plan via `community.windows`
(`win_domain_ou/_user/_group/_group_membership/_computer`) + small
`win_powershell` tasks for the two things no native module covers (AS-REP flag,
GenericAll ACL noise, mirroring the `dsacls` pattern in `templates/ansible/
vulns/`). Decision and application are now separate steps — that's what lets
`resolve_attack_chain()` (see `vuln-injection`) cast real, known population
objects into vuln roles at generate time.

## Still PurpleForge-authored

Theme `extra_groups` (`catalog/themes/<theme>.yml`) fold into the population
plan's group list (tagged `curated: true`); the old `ad_theming_overlay` role is
retired. `deception.honey_accounts`/`honey_account_naming` are NOT created here —
that's `defensive-controls`' job; this skill only exposes the naming pattern.

## Theme catalog format (`catalog/themes/<id>.yml`)

```yaml
id: medieval-kingdom
vocabulary:
  houses: [{ code: STK, name: "House Stark" }, ...]   # -> OU department codes
  given_names_male: [Eddard, ...]
  given_names_female: [Catelyn, ...]
  family_names: [Stark, ...]
extra_groups: [{ name: "Small Council", description: "..." }, ...]
honey_account_naming: "grand.maester.{n}"              # consumed by defensive-controls
```

`lab-spec` rejects a spec whose `lab.theme` has no matching file — adding a theme
is adding one YAML file. No job-title/manager fields (BadBlood didn't set them).

## Population sizing

`population.users` = direct user count. `GroupCount`/`ComputerCount` scale by
`population.density` (`forge.py:compute_population_counts`): `sparse` ×0.15/×0.3,
`realistic` ×0.2/×0.4, `messy` ×0.3/×0.5. Multi-domain: `users` split evenly
across populatable domains (no per-domain override in the schema).
`population.include_noise_acls` (default `true`) toggles random `GenericAll`
grants — set `false` for cleaner signal, e.g. `attack_chain.mode: ctf`.

## Testing (structural — no live DC)

```bash
python3 scripts/forge.py generate specs/<lab>.yml
python3 -c "
import json; m=json.load(open('generated/<lab>/lab-manifest.json'))
for p in m['population_plans']: print(p['domain'], len(p['users']),'users', len(p['groups']),'groups', len(p['ous']),'OUs')
"
cd generated/<lab>/ansible && ansible-playbook --syntax-check playbooks/ad-population.yml
```

Live: confirm `ad-population.yml` created the exact graph
(`Get-ADUser`/`Get-ADGroupMember` spot checks) — `forge.py ad-inventory` does
this comparison automatically.

---
name: ad-theming
description: >
  Deterministically generates each domain's entire AD population (OU tree,
  users, groups, computers, memberships, ACL noise) in Python
  (scripts/population.py), themed from the spec's lab.theme and seeded from
  population.seed — no BadBlood involved. Runs after ad-topology (domains/
  trusts must exist first), before vuln-injection, which casts real
  population objects into vulnerability roles.
---

# ad-theming

## When to use this skill

- During `/generate`, right after `ad-topology`'s inventory/playbook are
  rendered, to compute the population plan and render
  `ad-population.yml`.
- During `/deploy`, after AD topology is up (`ad-topology.yml` has run),
  before vulnerability injection — see CLAUDE.md's deploy order:
  `infra → ad-topology → ad-population → hardening → vulns → EDR → snapshot`.

## Why this isn't BadBlood anymore

Earlier versions of this skill wrapped `vendor/BadBlood/Invoke-BadBlood.ps1`
unmodified, theming it by overwriting the name-list/CSV files it reads and
seeding its `Get-Random` calls. That design had a hard limit: BadBlood's
randomness only happens on the live Windows host, at Ansible-runtime — so
`forge.py` could never know a population's actual usernames, passwords, or
OU placement ahead of a real deploy. `lab-report.md` had to carry an
explicit "names aren't predictable" caveat, and vuln-injection had to
synthesize its own separate `svc-*` accounts rather than reuse anything
BadBlood created.

**This is a deliberate, explicit departure from CLAUDE.md's "wrap mature
upstream projects rather than reinventing" principle, scoped specifically to
BadBlood** — confirmed with the user during the session that introduced
`scripts/population.py`. GOAD, Vulnerable-AD, and ansible-lockdown are still
wrapped exactly as before; only BadBlood's role is replaced.
`vendor/BadBlood` stays in the repo as a pinned, untouched submodule but is
no longer invoked by anything.

## How it actually works now

`scripts/population.py`'s `generate_population_plan()` is a pure Python
function, seeded with a single `random.Random(population.seed + offset)` —
simpler and *more* deterministic than BadBlood's own split mechanism
(CSPRNG for passwords, separate `Get-Random` for names, neither reproducible
from Python). It was written by reading BadBlood's actual PowerShell source
(`AD_Users_Create/CreateUsers.ps1`, `AD_Groups_Create/CreateGroup.ps1` +
`AddRandomToGroups.ps1`, `AD_Computers_Create/CreateComputers.ps1`,
`AD_OU_CreateStructure/CreateOUStructure.ps1`,
`AD_Permissions_Randomizer/GenerateRandomPermissions.ps1`) and reproducing
its actual ratios/naming patterns — the goal is to match BadBlood's
realism, not exceed it (see the module's own docstring for the exact
ratios: 3%/97% service/person account split, flat-random OU placement, 25%/
75% admin-group/distlist naming, 80% group-membership participation, etc.).

The one deliberate realism *change* from BadBlood: **every user's password
is generated and recorded**, never irrecoverable — the whole point of
replacing BadBlood was to document the full domain (including passwords)
ahead of deployment, per the user's explicit request.

`render_ad_population()` (`scripts/forge.py`) calls
`generate_population_plan()` once per populatable domain (root DC + child
DCs, same as BadBlood-era `attach_population_vars` did, same per-domain
seed-offset trick), then renders `templates/ansible/playbooks/
ad-population.yml.j2` — one Ansible play per domain that *applies* the
already-computed plan via native `community.windows` modules
(`win_domain_ou`, `win_domain_user`, `win_domain_group`,
`win_domain_group_membership`, `win_domain_computer`), plus small
`win_powershell` tasks for the two things no native module covers
(AS-REP-roastable flag, GenericAll ACL noise — mirroring the `dsacls`
pattern already used throughout `templates/ansible/vulns/`). The population
*decision* and the population *application* are now two separate steps —
this is what lets `resolve_attack_chain()` (see `vuln-injection/SKILL.md`)
cast real, already-known population objects into vulnerability roles at
generate time too, instead of creating synthetic `svc-*` accounts.

## What's still PurpleForge-authored on top

Theme `extra_groups` (`catalog/themes/<theme>.yml`) — `Small Council`,
`Kingsguard`, etc. for `medieval-kingdom` — fold directly into the same
population plan's group list now (tagged `curated: true`), rather than
being a separate `ad_theming_overlay` role bolted on afterward (that role
is retired). `deception.honey_accounts`/theme's `honey_account_naming` are
still *not* created here — seeding deception accounts remains
`defensive-controls`' job; this skill only exposes the naming pattern in
the catalog for that skill to consume.

## Theme catalog format (`catalog/themes/<id>.yml`)

```yaml
id: medieval-kingdom
vocabulary:
  houses: [{ code: STK, name: "House Stark" }, ...]   # -> OU tree department codes
  given_names_male: [Eddard, Robb, ...]
  given_names_female: [Catelyn, Sansa, ...]
  family_names: [Stark, Lannister, ...]
extra_groups: [{ name: "Small Council", description: "..." }, ...]
honey_account_naming: "grand.maester.{n}"              # consumed by defensive-controls, not here
```

`lab-spec`'s semantic checks reject a spec whose `lab.theme` has no matching
`catalog/themes/<theme>.yml` — adding a theme is adding one YAML file, same
philosophy as the vulnerability catalog. There's currently no field for job
titles/departments-as-attributes/manager relationships — BadBlood itself
never set those either, so matching its realism doesn't require them.

## Population sizing

`population.users` is the direct user count. `GroupCount`/`ComputerCount`
scale off it by `population.density`
(`scripts/forge.py:compute_population_counts`, unchanged from the
BadBlood-era logic): `sparse` → ×0.15/×0.3, `realistic` → ×0.2/×0.4,
`messy` → ×0.3/×0.5. In a multi-domain spec, `population.users` is split
evenly across every populatable domain (root + child domain controllers) —
there's no per-domain population override in the schema today.
`population.include_noise_acls` (default `true`) toggles the BadBlood-style
random `GenericAll` grants — set `false` for a cleaner signal-to-noise
ratio, e.g. when `attack_chain.mode: ctf`.

## Testing this skill

No live DC in CI. Validate structurally:

```bash
python3 scripts/forge.py generate specs/examples/medieval-2dom-azure.yml
# inspect the precomputed plan directly — no deploy needed for this check
python3 -c "
import json
m = json.load(open('generated/shadow-keep/lab-manifest.json'))
for p in m['population_plans']:
    print(p['domain'], len(p['users']), 'users', len(p['groups']), 'groups', len(p['ous']), 'OUs')
"
cd generated/shadow-keep/ansible && ansible-playbook --syntax-check playbooks/ad-population.yml
```

For a live deploy, confirm `ad-population.yml` actually created the exact
graph the plan specifies (`Get-ADUser`/`Get-ADGroupMember` spot checks
against a few plan entries) — `scripts/forge.py ad-inventory` does this
comparison automatically now (see its own header comment in `forge.py`).

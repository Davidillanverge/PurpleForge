---
name: ad-theming
description: >
  Populates each domain with realistic AD objects via vendor/BadBlood
  (unmodified) and renames its vocabulary (department codes, user names) to
  match the spec's lab.theme, deterministically via population.seed. Runs
  after ad-topology (domains/trusts must exist first), before vuln-injection.
---

# ad-theming

## When to use this skill

- During `/generate`, right after `ad-topology`'s inventory/playbook are
  rendered, to also render the themed BadBlood overlay and
  `ad-theming.yml` playbook.
- During `/deploy`, after AD topology is up (`ad-topology.yml` has run),
  before vulnerability injection — see CLAUDE.md's deploy order:
  `infra → ad-topology → ad-theming → hardening → vulns → EDR → snapshot`.

## Reuse, don't fork — how theming actually works

`vendor/BadBlood/Invoke-BadBlood.ps1` has no `-Theme` or `-Seed` parameter,
and there is no upstream project that themes AD population. Rather than
forking BadBlood or writing a population engine from scratch, this skill
exploits two things already present in BadBlood's own code, unmodified:

1. **`CreateUser`/`CreateComputer` take a `-ScriptDir` parameter** that
   determines where they load data from:
   `CreateUsers.ps1` reads
   `$ScriptDir\Names\{familynames,femalenames,malenames}-usa-top1000.txt`
   (`get-content ... | get-random`), and `CreateComputers.ps1` reads
   `(parent of $ScriptDir)\AD_OU_CreateStructure\3lettercodes.csv` for
   department-code-flavored computer name prefixes.
   `CreateOUStructure.ps1` reads that same CSV relative to *its own* location
   (not parameterized) for the Tier1/Tier2/Stage/People sub-OU names —
   because of this, theming works by **staging a full copy of
   `vendor/BadBlood`** per lab (`generated/<lab>/ansible/files/badblood/`)
   and overwriting just those two kinds of files in place
   (`scripts/forge.py:render_badblood_overlay`), rather than passing
   `-ScriptDir` around individually. The scripts themselves are copied
   byte-for-byte from `vendor/BadBlood` — nothing in them is patched.
   BadBlood's top-level OU skeleton itself (`Admin`, `Tier 0/1/2`, `People`,
   `Quarantine`, ...) is hardcoded PowerShell arrays inside
   `CreateOUStructure.ps1`, not data-file-driven, and is intentionally left
   alone — it's realistic IAM tiering scaffolding independent of theme.
2. **Every random draw in BadBlood goes through PowerShell's `Get-Random`
   cmdlet** (never raw `System.Random`), which respects a process-wide
   `Get-Random -SetSeed <n>`. `templates/ansible/playbooks/ad-theming.yml`
   sets the seed in the *same* `win_powershell` script block that then calls
   `Invoke-BadBlood.ps1`, so the whole population run for that domain is
   reproducible from `population.seed`. Multi-domain labs offset the seed by
   domain index (`scripts/forge.py:attach_population_vars`) so two domains
   don't draw an identical population.

`-SkipLapsInstall` is always passed to `Invoke-BadBlood.ps1` — LAPS is a
hardening control owned by `defensive-controls`
(`defense.hardening.controls.laps`), which lands in a later phase; letting
BadBlood install its own LAPS schema here would race with that.

## What's actually PurpleForge-authored

Everything above is BadBlood unmodified plus data-file substitution. The one
genuinely new piece is `templates/ansible/roles/ad_theming_overlay`: after
BadBlood has populated the domain, it creates the theme's `extra_groups`
(`catalog/themes/<theme>.yml`) as security groups — `Small Council`,
`Kingsguard`, etc. for `medieval-kingdom` — a concept BadBlood has no
equivalent for. `deception.honey_accounts`/theme's `honey_account_naming`
are *not* created here — seeding deception accounts is `defensive-controls`'
job (a later phase); this skill only exposes the naming pattern in the
catalog for that skill to consume.

## Theme catalog format (`catalog/themes/<id>.yml`)

```yaml
id: medieval-kingdom
vocabulary:
  houses: [{ code: STK, name: "House Stark" }, ...]   # -> 3lettercodes.csv
  given_names_male: [Eddard, Robb, ...]                # -> Names/malenames-usa-top1000.txt
  given_names_female: [Catelyn, Sansa, ...]            # -> Names/femalenames-usa-top1000.txt
  family_names: [Stark, Lannister, ...]                # -> Names/familynames-usa-top1000.txt
extra_groups: [{ name: "Small Council", description: "..." }, ...]
honey_account_naming: "grand.maester.{n}"              # consumed by defensive-controls, not here
```

`lab-spec`'s semantic checks reject a spec whose `lab.theme` has no matching
`catalog/themes/<theme>.yml` — adding a theme is adding one YAML file, same
philosophy as the vulnerability catalog.

## Population sizing

`population.users` is the direct `UserCount`. `GroupCount`/`ComputerCount`
scale off it by `population.density`
(`scripts/forge.py:compute_population_counts`): `sparse` → ×0.15/×0.3,
`realistic` → ×0.2/×0.4, `messy` → ×0.3/×0.5 (more groups/nesting noise). In
a multi-domain spec, `population.users` is split evenly across every
populatable domain (root + child domain controllers) — there's no per-domain
population override in the schema today.

## Testing this skill

No live DC in CI. Validate structurally:

```bash
python3 scripts/forge.py generate specs/examples/medieval-2dom-azure.yml
# check the overlay: line counts and CSV shape
wc -l generated/shadow-keep/ansible/files/badblood/AD_Users_Create/Names/*.txt
cat generated/shadow-keep/ansible/files/badblood/AD_OU_CreateStructure/3lettercodes.csv
cd generated/shadow-keep/ansible && ansible-playbook --syntax-check playbooks/ad-theming.yml
```

# PurpleForge

A specification-driven harness that turns a declarative `lab-spec.yml` into
complete automation (Terraform + Ansible + PowerShell) for deploying
**Purple-Team-instrumented Active Directory labs** on **AWS or Azure** —
including a configurable **defensive stack** (SIEM, EDR, hardening) deployed
alongside the intentional vulnerabilities.

PurpleForge does not reinvent Windows/AD deployment or endpoint hardening. It
wraps and reuses mature upstream projects, pinned as git submodules in
`vendor/`: **GOAD v3** (IaC + AD engine), **Splunk Attack Range** (design
reference for instrumentation), **BadBlood** (realistic population),
**Vulnerable-AD** (vulnerability primitives), and **ansible-lockdown**
(CIS/STIG hardening roles).

See `DISENO-purpleforge.md` for the full design rationale and
`PROMPT-claude-code.md` for the build brief this repository was generated
from.

## Philosophy

1. **Reuse, don't reinvent.** Thin generation layers over `vendor/`, not a
   second Terraform/Ansible engine.
2. **Spec-driven.** `specs/<lab>.yml` is the only hand-edited source of truth.
   Everything under `generated/<lab>/` is derived and reproducible.
3. **Purple = offense ∧ defense, coupled.** Every vulnerability in the
   catalog ships with `detect` + `mitigate` + `neutralized_by`. A lab without
   telemetry and controls is not a Purple Team lab.
4. **Offense and defense are reconciled, not just coexisting.** Hardening and
   intended vulnerabilities *will* conflict. PurpleForge resolves that
   conflict explicitly instead of ignoring it — see [Reconciliation](#hardening--vulnerability-reconciliation)
   below.
5. **Secure by construction.** VPN-only access, deny-by-default egress,
   auto-shutdown, and cost control are code, not documentation.

## Authorized use only

PurpleForge generates **isolated labs for authorized testing** — training,
purple teaming, and defensive research in environments you own or are
explicitly authorized to test. It does not generate payloads or automation
directed at third-party systems. See `CLAUDE.md` for the invariant rules this
repository is built to enforce (network isolation, cost/lifecycle limits,
mandatory detect+mitigate pairing, hardening⟷vuln reconciliation, remote
Terraform state).

## Repository layout

```
purpleforge/
├── CLAUDE.md                    # invariant rules for any agent working in this repo
├── .claude/
│   ├── commands/                # /new-lab /generate /deploy /validate /destroy (added as their skills land)
│   └── skills/                  # lab-spec, network-topology, infra-aws/azure, ad-topology,
│                                 # ad-theming, vuln-injection, detection-lab, defensive-controls, purple-validation
├── specs/
│   ├── schema/lab-spec.schema.json
│   └── examples/                # medieval-2dom-azure.yml, corp-espionage-aws.yml, single-dc-azure.yml
├── catalog/
│   ├── vulnerabilities/         # id.yml: attack + inject + detect + neutralized_by + mitigate + validate
│   ├── themes/                  # medieval-kingdom, corporate, space-station: vocabulary + extra_groups
│   ├── machine-profiles/        # (later phase) default OS/sizing per role, currently hardcoded in infra-azure
│   └── defense/
│       ├── profiles/            # none, telemetry-only, realistic, hardened
│       ├── edr/                 # per-product: backend_required + implementation notes (only defender-av: false)
│       └── hardening/           # cis-l1/cis-l2/stig/baseline-controls (role_by_os + tags_by_role) +
│                                 # control-cis-rules.yml (VERIFIED control -> concrete CIS rule mappings)
├── templates/
│   ├── terraform/azure/         # VNet/subnets/NSGs/WireGuard bastion (network-topology) +
│   │                             # Windows VMs/WinRM bootstrap (infra-azure); thin wrapper over vendor/GOAD
│   ├── terraform/aws/           # (Phase 8)
│   └── ansible/                 # ad-topology.yml + ad-theming.yml + vuln-injection.yml.j2 +
│                                 # defensive-controls.yml.j2 + vulns/<id>.yml + inventory template;
│                                 # roles_path resolves straight into vendor/GOAD/ansible/roles and
│                                 # vendor/ansible-lockdown — pf_controls/pf_defender_av/pf_deception/
│                                 # ad_theming_overlay are the only PurpleForge-authored roles
├── vendor/                      # git submodules, version-pinned: GOAD, attack_range, BadBlood,
│                                 # Vulnerable-AD, ansible-lockdown/Windows-*-CIS and -STIG
├── generated/                   # gitignored — output per lab: lab-manifest.json, terraform/, ansible/
└── scripts/
    └── forge.py                 # deterministic core: schema validation, semantic checks,
                                  # defense.profile resolution, IP/topology plan, cost estimate,
                                  # reconciliation, and (for azure) Terraform/Ansible rendering
```

## Getting started

```bash
git clone --recurse-submodules <this-repo>
# or, if already cloned:
git submodule update --init --recursive

python3 -m venv .venv && source .venv/bin/activate
pip install -r scripts/requirements.txt
```

`terraform` (>= 1.5) is only needed for `scripts/forge.py generate ... --plan`; without
it, `generate` still renders every file, it just skips the plan step.

## The `lab-spec.yml` flow

```
/new-lab "2 domains medieval, ESC1+Kerberoast, Azure, Elastic + Defender AV + CIS L1"
/generate shadow-keep --dry-run
/generate shadow-keep
/deploy shadow-keep          # hardening baseline -> inject gaps -> EDR/telemetry -> clean snapshot
/validate shadow-keep        # does the path exist? prevented/detected/not seen? -> lab-report.md
/destroy shadow-keep
```

- **`/new-lab`** — turns a natural-language description into a validated
  `specs/<name>.yml` (asks for the defense profile/stack if not specified).
- **`/generate`** — runs every generation skill and the hardening⟷vuln
  reconciliation, producing `generated/<lab>/` (Terraform, Ansible inventory
  and playbooks, `lab-manifest.json`).
- **`/deploy`** — preflight checks, `terraform apply`, then playbooks in
  order: infra → AD topology → population/theming → **hardening baseline** →
  **selective vulnerability injection (the gaps)** → **EDR + telemetry** →
  **clean-state snapshot** (always taken *before* any attack is run).
- **`/validate`** — SharpHound→BloodHound (path exists?), PingCastle
  (posture), and Atomic Red Team techniques, classifying each as
  **PREVENTED / DETECTED / NOT SEEN** in `lab-report.md`.
- **`/destroy`** — `terraform destroy` plus a zero-cost check.

> **Status:** `lab-spec` (validation/reconciliation/manifest) and, for Azure,
> `network-topology` + `infra-azure` + `ad-topology` + `ad-theming` +
> `vuln-injection` + `defensive-controls` (Terraform + Ansible generation,
> themed/seeded BadBlood population, catalog-driven vulnerability injection,
> ansible-lockdown hardening with reconciliation-derived skip_rules, EDR,
> deception) are implemented end-to-end — see `PROMPT-claude-code.md`
> §"Orden de trabajo" for the phase-by-phase roadmap. **`detection-lab` is
> deliberately not built** — this project stops at PREVENT/RESPOND, it does
> not stand up a SIEM. `infra-aws`, `purple-validation`, and the slash
> commands themselves land in later phases. You can already validate+reconcile
> a spec, or generate real Terraform/Ansible + themed population + injected
> vulns + hardening/EDR/deception for a single-domain Azure lab, directly:
>
> ```bash
> python3 scripts/forge.py lab-spec specs/examples/medieval-2dom-azure.yml
> # writes generated/shadow-keep/lab-manifest.json
>
> python3 scripts/forge.py generate specs/examples/single-dc-azure.yml --plan
> # writes generated/single-dc-test/{terraform/azure,ansible}/ and, if
> # terraform is on PATH, runs init -backend=false/validate/plan for structural
> # checking (this deliberately skips remote state — a real deploy uses the
> # generated backend.hcl against a bootstrapped storage account instead; see
> # .claude/skills/infra-azure/SKILL.md. `plan` needs az login/ARM_* credentials
> # to get past provider auth)
> ```

## Custom machine images

`machines[]` entries can point at an existing image instead of the
marketplace publisher/offer/sku PurpleForge picks for `os` — e.g. a golden
workstation image with an EDR agent already installed:

```yaml
machines:
  - role: workstation
    os: windows-11-23h2      # still required — drives hardening/OS-specific behavior regardless of the image
    domain: kingdom.local
    count: 2
    image_id: "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/galleries/<gallery>/images/<def>/versions/<ver>"
```

Azure accepts either a managed image or a Shared Image Gallery version
resource ID (`infra-azure` swaps in `source_image_id` for that machine group
via a `dynamic` block, since it's mutually exclusive with the marketplace
`source_image_reference`). The field is named provider-agnostically
(`image_id`, not `azure_image_id`) so it can hold an AWS AMI id once
`infra-aws` exists — nothing consumes it for AWS today. `os` stays required
either way, since it still selects the ansible-lockdown role/OS-specific
Ansible behavior independent of which image backs the VM.

## The `defense:` block

Every `lab-spec.yml` declares not just what's vulnerable, but what defensive
stack is deployed alongside it:

```yaml
defense:
  profile: realistic                 # none | telemetry-only | realistic | hardened
  siem:    { platform: elastic, ship_sysmon: true, ship_wef: true, network_monitoring: [zeek] }
  edr:
    - { product: defender-av, mode: enabled, settings: { asr_rules: audit }, targets: all }
    - { product: elastic-defend, mode: prevent, targets: [domain-controller, member-server] }
  hardening:
    baseline: cis-l1                 # none | cis-l1 | cis-l2 | stig | baseline-controls
    apply_to: all
    controls: { laps: true, lsa_protection: true, smb_signing: enforce, ldap_signing: enforce, ... }
    intentional_gaps_auto: true      # derive hardening exclusions from each vuln's neutralized_by
  deception: { honey_accounts: 3, canarytokens: [docx, aws-keys] }

on_conflict: exclude-control         # warn | exclude-control | fail
```

`profile` fixes sensible defaults (`catalog/defense/profiles/<profile>.yml`);
everything under `siem`/`edr`/`hardening`/`deception` is a fine-grained
override layered on top.

| Profile | Deploys | For |
|---|---|---|
| `none` | nothing | purely offensive practice |
| `telemetry-only` | Sysmon + WEF + SIEM, no prevention | pure detection engineering |
| `realistic` | Defender AV (ASR audit) + CIS L1 (with intentional gaps) + SIEM + 1 EDR | the most representative mid-size-company scenario |
| `hardened` | CIS L2/STIG + EDR in prevent + ASR enforce + LAPS + Credential Guard | evasion/detection stress-testing |

## Hardening ⟷ vulnerability reconciliation

Hardening and intentional vulnerabilities can select conflicting outcomes —
e.g. a CIS L1 baseline can include the exact rule that purges the
`gpp-cpassword` weakness you asked for. Rather than silently letting one win,
`lab-spec` cross-references each selected `vulnerabilities[]` entry's
`neutralized_by` field (in its `catalog/vulnerabilities/<id>.yml`) against
the resolved `defense.hardening`, and resolves the conflict per `on_conflict`:

- **`exclude-control`** (recommended default, paired with
  `intentional_gaps_auto: true`) — excludes the specific conflicting rule,
  leaving the rest of the baseline intact. *Result: a mostly-hardened
  environment with specific, deliberate gaps — the most realistic and useful
  scenario.* Recorded in `lab-manifest.json` under `reconciliation.excluded_controls`,
  with the reason for each exclusion.
- **`warn`** — applies hardening as configured and lists which vulnerabilities
  might end up neutralized, without changing anything.
- **`fail`** — stops generation and asks you to resolve the conflict in the
  spec.

Try it:

```bash
python3 scripts/forge.py lab-spec specs/examples/medieval-2dom-azure.yml
```

This spec deliberately selects `gpp-cpassword` together with
`hardening.baseline: cis-l1`, which genuinely conflict — the run reports the
exclusion PurpleForge derives so the gap stays open while the rest of CIS L1
still applies.

## Theming and population

`lab.theme` + `population` drive a themed, deterministic BadBlood run per
domain — no fork of `vendor/BadBlood`, only data-file substitution:

```yaml
lab:      { theme: medieval-kingdom, ... }
population: { users: 300, density: realistic, seed: 1337 }
```

`population.users` becomes BadBlood's `UserCount` directly;
`GroupCount`/`ComputerCount` scale off it by `density`. `catalog/themes/<theme>.yml`'s
vocabulary (department "house" codes, given/family name pools) overwrites
BadBlood's own `Names/*.txt`/`3lettercodes.csv` at the exact paths its
scripts already read from, and `Get-Random -SetSeed population.seed` (offset
per domain in a multi-domain forest) makes the whole run reproducible —
BadBlood consistently draws randomness through `Get-Random`, which honors a
process-wide seed. See `.claude/skills/ad-theming/SKILL.md` for the full
mechanism, including the one genuinely new piece (no BadBlood equivalent):
`extra_groups`, theme-specific privileged groups layered on top after
BadBlood populates the domain.

```bash
python3 scripts/forge.py generate specs/examples/medieval-2dom-azure.yml
cat generated/shadow-keep/ansible/files/badblood/AD_OU_CreateStructure/3lettercodes.csv
```

## Vulnerability catalog

Adding a vulnerability is adding a self-contained YAML file in
`catalog/vulnerabilities/` — no generator code changes required:

```yaml
id: adcs-esc1
severity: critical
attack:   { mitre_attack: [T1649], requires_services: [adcs], intended_path: "..." }
inject:   { type: ansible, playbook: templates/ansible/vulns/adcs_esc1.yml, params: {...} }
detect:   { data_source: "...", signal: "...", siem_rule: templates/detection/{siem}/adcs_esc1 }
neutralized_by: [hardening.controls.adcs_template_hardening, {hardening.baseline: [cis-l2]}]
mitigate: { summary: "..." }
validate: { bloodhound_edge: ADCSESC1, atomic: T1649 }
```

15 entries ship today: `kerberoasting`, `asreproast`, `adcs-esc1`,
`unconstrained-delegation`, `constrained-delegation`, `gpp-cpassword`,
`dcsync-acl`, `passwords-in-description`, `smb-signing-disabled`,
`ntlm-downgrade`, `laps-read-acl`, `shadow-credentials`,
`dnsadmins-privesc`, `rbcd-abuse`, `backup-operators-membership` — see
`vuln-injection/SKILL.md`'s "Adding a vuln" section for the checklist to add
another.

## Vulnerability injection

`generate` turns each id in the spec's `vulnerabilities[]` into an idempotent
Ansible play (`ansible/playbooks/vuln-injection.yml` + `ansible/vulns/<id>.yml`),
targeting the right host and recording the intended attack path plus a
reconciliation-derived neutralization status per vuln in `lab-manifest.json`:

```
$ python3 scripts/forge.py generate specs/examples/medieval-2dom-azure.yml
  wrote ansible/playbooks/vuln-injection.yml + ansible/vulns/ (4 vuln(s))
      - kerberoasting -> kingdom-dc01  [clear]
      - adcs-esc1     -> kingdom-mbr01 [clear]           # runs on the ADCS host
      - gpp-cpassword -> kingdom-dc01  [gap-preserved]   # its cis-l1 conflict was excluded
      - dcsync-acl    -> kingdom-dc01  [clear]
```

Injected artifacts are **named and deterministic** (e.g. `svc-sqlreport` with
an SPN for kerberoasting), not the random-user picks Vulnerable-AD's own
functions make — that keeps the playbooks idempotent and seed-stable
(invariant #5). Upstream is reused where it fits: `adcs-esc1` installs GOAD's
ready-made ESC1 template; `dcsync-acl` extends GOAD's `acls` technique with the
replication GUIDs. The `neutralization` tag (`gap-preserved` / `AT RISK` /
`clear`) is how "vuln-injection respects the reconciliation exclusions" is made
concrete — see `.claude/skills/vuln-injection/SKILL.md`.

## Defensive controls (PREVENT/RESPOND — no SIEM)

`generate` also renders `ansible/playbooks/defensive-controls.yml`: the
resolved `defense.hardening` baseline via the pinned
`vendor/ansible-lockdown` roles (with `skip_rules` derived from the
reconciliation — this is where "exclude the concrete rule" becomes an actual
`winXXcis_rule_N_N_N: false`, not just a manifest note), EDR (Microsoft
Defender Antivirus only — every other product needs a management backend
this project deliberately does not build), and deception (theme-named honey
accounts). **`detection-lab` does not exist in this project** — no
Sysmon/WEF/SIEM is stood up; this is PREVENT/RESPOND only.

Only two of the seed vulns have a **verified** ansible-lockdown rule mapping
(`smb-signing-disabled` ↔ CIS 2.3.8.x/2.3.9.x, and `unconstrained-delegation`
↔ RunAsPPL, which turned out to be in ansible-lockdown's `ngws` profile, not
the default `level1`/`level2` — an earlier, unverified `hardening.baseline:
[cis-l2]` claim for it was removed once checked against the actual role). The
rest of the seed vulns' `neutralized_by` baseline entries are conceptual —
audited against the pinned CIS roles and found to have no matching rule —
and `defensive-controls` reports that honestly instead of guessing:

```
$ python3 scripts/forge.py generate specs/examples/medieval-2dom-azure.yml
  wrote ansible/playbooks/defensive-controls.yml (baseline: cis-l1, 3 OS group(s))
      note: vuln 'gpp-cpassword': baseline-level exclusion (control label 'gpp_cpassword_removed') has no verified ansible-lockdown rule mapping in control-cis-rules.yml — no skip_rule applied.
      note: edr 'elastic-defend' — 'elastic-defend' needs a management backend this project does not build (no detection-lab) — recorded, not silently skipped.
```

See `.claude/skills/defensive-controls/SKILL.md` for the full honesty model,
why CIS level selection needs `--tags` at `ansible-playbook` invocation time
(not just tags on the role include), and three real bugs three levels of
testing (YAML parsing, not just generation) caught during this phase.

## The lab report (`lab-report.md`)

`generate` also writes `generated/<lab>/lab-report.md` — the same data as
`lab-manifest.json`, rendered as human-readable documentation: machines,
network topology, the AD forest, population counts, this harness's own
theme-driven AD groups, hardening applied (baseline + fixed controls, with
the exact `--tags` value and any reconciliation exclusions), EDR, and every
injected vulnerability with its target host and neutralization status.

**It also contains every generated secret** — domain admin passwords per
domain, the WinRM automation account, the local VM administrator, and each
vulnerability-injection account's password — so it lives in
`generated/<lab>/` (gitignored) right alongside the manifest, never
committed, never shared outside the lab's authorized operators.

**What it deliberately does NOT show**: the literal usernames/group names
BadBlood will create, or the honey accounts' passwords. Both are randomized
at *deploy time* on the Windows host itself (BadBlood through PowerShell's
`Get-Random`, honey accounts through an Ansible `lookup()` plugin) — Python
can't reproduce .NET's RNG sequence from the same integer seed, so claiming
otherwise here would be exactly the kind of unverified claim this project
has repeatedly caught and corrected (see Defensive controls, above). Only
the *counts* and the seed itself are known ahead of deployment; query the
live domain for the real names after `/deploy` — see `ad-inventory`, next.

## Post-deploy AD inventory (`forge.py ad-inventory`)

`lab-report.md` is spec-time and can never show the real usernames — but
once the lab is actually deployed and reachable (WireGuard tunnel up),

```bash
python3 scripts/forge.py ad-inventory specs/examples/<lab>.yml
# writes generated/<lab>/ad-inventory.md
```

queries the live domain directly (LDAP via `ldap3` for every user + group +
membership, `nxc`/netexec for an NTDS hash dump via DCSync) and renders
every user (NT hash, group memberships, tagged `VULN:<id>` if it's one of
the injected vulnerability accounts, tagged `PRIV` if it's in a privileged
group) and every group (description, full member list). This is
deliberately NOT plaintext passwords: BadBlood's own per-user passwords are
randomly generated with PowerShell's `Get-Random` on the DC and never
written anywhere — not recoverable by this project or anyone else after the
fact. NT hashes genuinely are stored in AD and DCSync-recoverable, and are
directly usable (pass-the-hash) or crackable offline (`hashcat -m 1000`),
so this is the honest equivalent for a live domain. Same sensitivity as
`lab-report.md` — gitignored, never commit it, re-run anytime the domain
changes (it always reflects current state, not original intent).

## Deploy order: `site.yml` is the entry point

`generate` also writes `ansible/playbooks/site.yml`, importing
`ad-topology.yml` → `ad-theming.yml` → `defensive-controls.yml` →
`vuln-injection.yml` (only if the spec has any vulnerabilities) in that
order — this is what makes "hardening applies before vulnerabilities are
injected" (CLAUDE.md's deploy-order invariant) actually true rather than
dependent on whoever runs `/deploy` invoking the individual playbooks by
hand. **Run `site.yml`, not the individual playbooks.**

**Known gap:** CLAUDE.md's deploy order also calls for a clean-state snapshot
after vuln-injection and before any attack, so a purple-team exercise can
reset between runs. No snapshot mechanism exists yet — it needs either an
`azurerm` VM/managed-disk snapshot resource or an Ansible-side equivalent,
wired into a real `/deploy` orchestrator, and neither has been built or
tested against a live Azure subscription. `site.yml`'s own header comment
carries this same note — don't assume "reset between exercises" works
because the playbook runs cleanly today.

## Deploying a generated lab (manual, until `/deploy` exists)

`generate` only renders artifacts into `generated/<lab>/` — gitignored,
reproducible from the spec at any time, never itself the deployment. No
`/deploy` command exists yet to chain the steps below automatically; today
they're run by hand, in this order.

> **First real deploy done, and it's a checklist now, not a discovery
> exercise.** [`AZURE-DEPLOY-RUNBOOK.md`](AZURE-DEPLOY-RUNBOOK.md) is a
> procedural, copy-pasteable version of the steps below, with every gotcha
> hit during that deploy (quota, image generation mismatches, a Windows
> Firewall default that silently blocks cross-subnet WinRM, an NTLM/CBT
> quirk against domain controllers, and more) folded in as a preemptive step
> or a documented already-fixed callout. Start there for an actual Azure
> deploy; keep reading here for the conceptual walkthrough.

### Prerequisites

- `terraform` >= 1.5, `az` CLI (logged in: `az login`)
- `ansible-core` pinned to the version GOAD itself was validated against —
  `vendor/GOAD/requirements.yml` fixes `ansible-core==2.12.6`, which requires
  a **Python 3.8–3.10 control node** (it crashes on 3.11/3.12 — a Python
  import-hook incompatibility, not an ansible.cfg setting). If your host
  Python is newer, don't fight it with pyenv/deadsnakes — run Ansible inside
  a `python:3.10-slim` Docker container instead (`--network host` so it can
  see your WireGuard interface); see `AZURE-DEPLOY-RUNBOOK.md` step 6 for the
  exact commands, including the `community.general` Galaxy-client
  workaround. Otherwise, use a venv on Python 3.10:
  `pip install -r vendor/GOAD/requirements.yml`
- The collections GOAD itself depends on, pinned to the same versions:
  `ansible-galaxy collection install -r vendor/GOAD/ansible/requirements.yml`
  (newer `community.windows`/`ansible.windows` remove modules — e.g.
  `win_domain`, `win_domain_group` — that GOAD's roles still use; installing
  a newer collection version than this pin will break `ad-topology.yml`.
  **`community.general`, unpinned in that same file, will fail to install
  under `ansible-core` 2.12.6's Galaxy client** — see the runbook for the
  direct-tarball-download workaround.)
- A WireGuard client (the only way to reach anything in the lab — see
  CLAUDE.md invariant #1)

### 1. Bootstrap remote Terraform state (once per Azure subscription)

`versions.tf` declares a partial `backend "azurerm" {}` on purpose — it
never falls back to local state (CLAUDE.md invariant #4). The storage
account has to exist before any lab's own `terraform init` can point at it:

```bash
az group create -n purpleforge-tfstate-rg -l westeurope
az storage account create -n <globally-unique-name> -g purpleforge-tfstate-rg -l westeurope --sku Standard_LRS
az storage container create -n tfstate --account-name <globally-unique-name>
```

Edit `generated/<lab>/terraform/azure/backend.hcl`'s `storage_account_name`
to match — the generated placeholder (`purpleforgetfstate`) is not real,
Azure storage account names are a global namespace. One storage account
serves every lab (one blob key per lab, from `lab.name`), it is not
per-lab. See `.claude/skills/infra-azure/SKILL.md`.

### 2. Apply the infrastructure

```bash
cd generated/<lab>/terraform/azure
terraform init -backend-config=backend.hcl
terraform apply
```

Creates the isolated VNet, the WireGuard bastion (the only host with a
public IP), and the Windows VMs (private-IP-only, unreachable except
through the bastion). `terraform output bastion_public_ip` gives you the
address for the next step.

### 3. Connect over WireGuard

No peer is provisioned automatically — this is a manual, documented step
(see `.claude/skills/network-topology/SKILL.md`):

```bash
ssh -i ssh_keys/bastion.pem purpleforge@<bastion_public_ip>
sudo cat /etc/wireguard/publickey        # generated on first boot, not known to Terraform
sudo wg set wg0 peer <your-client-pubkey> allowed-ips <your-tunnel-ip>/32
```

Point your local WireGuard client at `<bastion_public_ip>:51820` with that
server public key. Only once connected can you reach the management subnet
and, through it, every port on the Windows hosts (WinRM, SMB, RDP, ...) —
there is no other path to them.

### 4. Deploy AD topology, theming, hardening, and vulnerabilities

```bash
cd ../../ansible
ansible-playbook -i inventory/hosts.yml playbooks/site.yml
```

`site.yml` is the single entry point — it already sequences
ad-topology → ad-theming → defensive-controls (hardening, in the CIS/STIG
level ansible-lockdown's own README documents as `--tags`-selected; see
`.claude/skills/defensive-controls/SKILL.md` for the exact `--tags` value
your baseline needs) → vuln-injection, so hardening always lands before the
intentional gaps, per CLAUDE.md's deploy-order invariant.

### Validating what actually got applied

`site.yml` running cleanly proves Ansible executed without error — it
doesn't prove the live host state matches what `lab-report.md` says was
*intended*. Two ways to check, both from `generated/<lab>/ansible/`:

**1. `verify.yml` — automated, but unverified against a real host** (this
repo has never had a live Windows host to test it against; read as
"syntax-checked and carefully cross-referenced against each injection
task's own logic," not "proven correct against a real deploy"):

```bash
ansible-playbook -i inventory/hosts.yml playbooks/verify.yml
```

It checks, per host, exactly what `lab-report.md` says was requested: AD
DNSRoot + BadBlood population counts and each theme's `extra_groups` on the
domain controllers; every fixed hardening control from `defense.hardening`
(LSA PPL, SMB signing, NTLMv2-only, Credential Guard, LLMNR/NBT-NS/mDNS,
LAPS, plus LDAP signing and Protected Users membership on DCs only); Defender
AV's real-time/network/tamper protection and ASR rule IDs when `defender-av`
is configured; and, per injected vulnerability, the specific registry key,
SPN, ACE, or account property that catalog entry sets — printing
`SKIPPED: no verify.yml check exists yet` for any vulnerability id it
doesn't have a check for yet.

**2. Ad-hoc commands, spot-checking anything `verify.yml` doesn't cover** —
`lab-report.md` has the exact account names/target hosts/expected values for
*your* lab; the examples below use `medieval-2dom-azure`'s:

```bash
# Connectivity
ansible all -i inventory/hosts.yml -m ansible.windows.win_ping

# AD domain / DC count / trust (child domain's trust to its parent is automatic)
ansible domain_controllers -i inventory/hosts.yml -m ansible.windows.win_shell \
  -a "Get-ADDomain | Select-Object DNSRoot,DomainMode"
ansible child_domain_controllers -i inventory/hosts.yml -m ansible.windows.win_shell \
  -a "Get-ADTrust -Filter *"

# Population (BadBlood) — counts only, literal names aren't predictable from the spec (see Theming)
ansible domain_controllers:child_domain_controllers -i inventory/hosts.yml -m ansible.windows.win_shell \
  -a "'{0} users, {1} groups, {2} computers' -f (Get-ADUser -Filter *).Count,(Get-ADGroup -Filter *).Count,(Get-ADComputer -Filter *).Count"

# A theme group (one per catalog/themes/<theme>.yml's extra_groups — names in lab-report.md)
ansible domain_controllers -i inventory/hosts.yml -m ansible.windows.win_shell -a "Get-ADGroup -Identity 'Small Council'"

# Hardening — pick the control from lab-report.md's "Fixed controls" table
ansible all -i inventory/hosts.yml -m ansible.windows.win_shell \
  -a "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LMCompatibilityLevel,RunAsPPL -ErrorAction SilentlyContinue"
ansible all -i inventory/hosts.yml -m ansible.windows.win_shell \
  -a "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature"

# EDR (Defender AV)
ansible all -i inventory/hosts.yml -m ansible.windows.win_shell \
  -a "Get-MpPreference | Select-Object DisableRealtimeMonitoring,EnableNetworkProtection,AttackSurfaceReductionRules_Ids"

# A vulnerability — account name/target host from lab-report.md's "Vulnerability-injection accounts" table
ansible kingdom-dc01 -i inventory/hosts.yml -m ansible.windows.win_shell \
  -a "Get-ADUser -Identity svc-sqlreport -Properties ServicePrincipalNames | Select -ExpandProperty ServicePrincipalNames"
```

### Tearing down: `forge.py destroy`

`terraform destroy` alone only removes what Terraform's own state tracks —
it doesn't prove nothing billable was left behind (a failed partial destroy,
a resource created out-of-band, etc.). `forge.py destroy` runs it and then
independently asks Azure whether the lab's resource group (everything a lab
creates lives inside the one `azurerm_resource_group` named after
`lab.name`) is actually gone, rather than trusting a clean Terraform exit
code:

```bash
python3 scripts/forge.py destroy specs/examples/simpsons-lab-azure.yml
#   terraform init -backend-config=backend.hcl (same backend.hcl deploy used)
#   terraform destroy                           (interactive confirmation, same as plain terraform)
#   az group show -n springfield-lab             <- the actual verification step
# OK: springfield-lab destroyed and verified — no expected leftover cost.
```

- `--check-only` runs `terraform plan -destroy` instead of destroying
  anything — preview only.
- `--yes` passes `-auto-approve` to `terraform destroy` (default: Terraform's
  own interactive prompt, not bypassed unless you ask).
- The `az group show` check distinguishes "confirmed gone"
  (`ResourceGroupNotFound`) from "az CLI errored for some other reason, e.g.
  not logged in" — an ambiguous error is reported as *could not verify*, not
  silently treated as a successful teardown. If `az` isn't installed at all,
  the check is skipped with an explicit warning rather than failing.
- If a lab was generated for more than one provider, it iterates every
  `terraform/<provider>/` subdirectory found; only `azure` has a
  post-destroy verification implemented today.

### What's still manual / missing

- Steps 1–4 above (deploy) are not chained by any `/deploy` command yet.
- Adding a WireGuard peer (step 3) has no helper script.
- No clean-state snapshot exists after step 4 and before an attack — see
  the "Known gap" note just above.
- `forge.py destroy` isn't wired to a `/destroy` slash command yet — run it
  directly.

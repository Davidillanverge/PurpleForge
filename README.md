# PurpleForge

A spec-driven harness that turns a declarative `lab-spec.yml` into complete
automation (Terraform + Ansible + PowerShell) for deploying **Purple-Team AD
labs** on **Azure or on-prem Proxmox VE** (AWS on the roadmap) — with a
configurable **defensive stack** (CIS/STIG hardening, Defender AV, deception)
deployed alongside the intentional vulnerabilities.

It wraps mature upstream projects pinned as submodules in `vendor/`: **GOAD v3**
(IaC + AD engine), **Vulnerable-AD** (vuln primitives), **ansible-lockdown**
(CIS/STIG roles). See `CLAUDE.md` for invariants + deploy order,
`.claude/agents/README.md` for the agent system; deterministic logic is in
`scripts/forge.py`.

## Philosophy

1. **Reuse, don't reinvent** — thin generation layers over `vendor/`.
2. **Spec-driven** — `specs/<lab>.yml` is the only hand-edited source; everything
   under `generated/<lab>/` is derived and reproducible.
3. **Purple = offense ∧ defense, coupled** — every catalog vuln ships
   detect+mitigate+neutralized_by.
4. **Offense and defense are reconciled**, not just coexisting (see below).
5. **Secure by construction** — VPN-only, deny-by-default, auto-shutdown, cost
   control are code.

**Authorized use only.** Isolated labs for testing you own or are authorized to
test. No payloads or automation aimed at third-party systems.

## Repository layout

```
CLAUDE.md            # invariant rules for any agent in this repo
.claude/
  commands/          # /new-lab /deploy /validate /destroy
  skills/            # lab-spec, network-topology, infra-azure/proxmox, ad-topology,
                     #   ad-theming, vuln-injection, defensive-controls, purple-validation
specs/
  schema/lab-spec.schema.json   # your hand-written/AI-generated <lab>.yml live here (not committed)
catalog/
  vulnerabilities/   # <id>.yml: attack + inject + neutralized_by + mitigate + validate
  themes/            # vocabulary + extra_groups
  defense/           # profiles/, edr/ (only defender-av), hardening/ (+ control-cis-rules.yml)
templates/
  terraform/azure/   # VNet/NSGs/bastion + Windows VMs (thin wrapper over vendor/GOAD)
  terraform/proxmox/ # on-prem: pool/firewall/VLANs + cloned VMs + bastion
  ansible/           # ad-topology/-population/vuln-injection/defensive-controls + inventory
vendor/              # version-pinned submodules: GOAD, Vulnerable-AD, ansible-lockdown
generated/           # gitignored — per-lab output: lab-manifest.json, terraform/, ansible/
scripts/forge.py     # deterministic core: validation, reconciliation, IP plan, cost, render
```

## Getting started

```bash
git clone --recurse-submodules <this-repo>   # or: git submodule update --init --recursive
python3 -m venv .venv && source .venv/bin/activate
pip install -e .            # runtime; puts `forge` on PATH
# ...or dev (linters, type-checker, tests):
pip install -e ".[dev]"
```

`forge lab-spec …` works anywhere after the editable install (used interchangeably
with `python3 scripts/forge.py …` below). `terraform` (>= 1.5) is only needed for
`generate … --plan`; without it, `generate` renders everything and skips the plan.

### Developing on the harness

Covered by a test suite — the deterministic core (manifests, plan, guardrail,
catalog) and the generated Terraform/Ansible artifacts. Run locally:

```bash
pytest                                  # invariant + unit + guardrail + catalog tests
ruff check . && ruff format --check .   # optional: lint + format
mypy                                    # optional: type-check scripts/
```

The tests own their inputs — they build specs in code with `make_spec()`
(`tests/_helpers.py`) and assert **invariants that hold for any spec** (IP plan has
no collisions and stays in-subnet, reconciliation excludes/warns on conflicts, cost
is per-provider, resolution is deterministic). There are no committed example specs
or golden files to keep in sync — add or extend a `make_spec()` case to cover a new
path.

## Create a lab

A lab is one YAML spec in `specs/`. Write it by hand from an example, or let
`/new-lab` turn a description into a validated spec:

```bash
/new-lab "2 medieval domains, ESC1 + Kerberoasting, Azure, Defender AV + CIS L1"
```

Everything after the spec exists is a plain `forge.py` command (no AI):

```bash
python3 scripts/forge.py generate specs/<lab>.yml          # render TF + Ansible + deploy.sh/teardown.sh
python3 scripts/forge.py deploy   specs/<lab>.yml          # build the lab
python3 scripts/forge.py validate specs/<lab>.yml --run    # check vulns are live + exploitable
python3 scripts/forge.py teardown specs/<lab>.yml          # destroy, back to zero cost
```

`generate` writes a self-contained `generated/<lab>/` (Terraform, Ansible,
`lab-report.md` with every credential + attack path, `deploy.sh`/`teardown.sh`).
It's gitignored — to share a lab, share its `specs/<lab>.yml` (determinism
guarantees byte-identical artifacts). Pick where it runs with `provider: azure`
or `provider: proxmox`.

> **Status:** the full Azure lifecycle (generate → deploy → validate → teardown)
> is deterministic today; Proxmox generate + deploy work the same. Scope stops at
> PREVENT/RESPOND (hardening + Defender AV) — no SIEM — and AWS is on the roadmap.

## The `defense:` block

Every spec declares its defensive stack alongside the vulnerabilities:

```yaml
defense:
  profile: realistic                 # none | realistic | hardened
  edr:
    - { product: defender-av, mode: enabled, settings: { asr_rules: audit }, targets: all }
  hardening:
    baseline: cis-l1                 # none | cis-l1 | cis-l2 | stig | baseline-controls
    apply_to: all
    controls: { laps: true, lsa_protection: true, smb_signing: enforce, ldap_signing: enforce }
    intentional_gaps_auto: true      # derive hardening exclusions from each vuln's neutralized_by
  deception: { honey_accounts: 3 }
on_conflict: exclude-control         # warn | exclude-control | fail
```

`profile` sets defaults (`catalog/defense/profiles/<profile>.yml`); `edr`/
`hardening`/`deception` override on top.

| Profile | Deploys | For |
|---|---|---|
| `none` | nothing | purely offensive practice |
| `realistic` | Defender AV (ASR audit) + CIS L1 (with gaps) + honey accounts | representative mid-size company |
| `hardened` | CIS L2/STIG + ASR enforce + LAPS + Credential Guard | evasion/hardening stress-testing |

> **Scope:** PREVENT/RESPOND only — CIS/STIG hardening, Defender AV, deception. No
> SIEM/Sysmon/WEF telemetry; detection engineering is out of scope for now.
> Defender AV is the only supported EDR (others need a management backend).

## Hardening ⟷ vulnerability reconciliation

Hardening and intended vulns can conflict (a CIS L1 baseline may include the exact
rule that purges the `gpp-cpassword` you asked for). `lab-spec` cross-references
each vuln's `neutralized_by` against the resolved `defense.hardening` and resolves
per `on_conflict`:

- **`exclude-control`** (recommended, with `intentional_gaps_auto: true`) —
  excludes the conflicting rule, keeps the rest of the baseline. A mostly-hardened
  environment with deliberate gaps. Recorded in
  `reconciliation.excluded_controls`.
- **`warn`** — applies hardening, lists which vulns might get neutralized, changes
  nothing.
- **`fail`** — stops generation; resolve it in the spec.

```bash
# a spec that selects gpp-cpassword under hardening.baseline: cis-l1 genuinely
# conflicts — lab-spec reports the exclusion it derives to keep the gap open:
python3 scripts/forge.py lab-spec specs/<lab>.yml
```

## Theming and population

`lab.theme` + `population` drive a themed, fully deterministic population (OUs,
users with passwords, groups, computers), computed in Python
(`scripts/population.py`) before any deploy:

```yaml
lab:      { theme: medieval-kingdom, ... }
population: { users: 300, density: realistic, seed: 1337 }
```

`population.users` is the user count; groups/computers scale off it by `density`.
`catalog/themes/<theme>.yml`'s vocabulary feeds the generator;
`random.Random(seed)` (offset per domain) makes it reproducible. Theme
`extra_groups` fold into the same plan (tagged `curated: true`). Replaced an
earlier BadBlood design (`vendor/BadBlood` stays pinned but unused; see
`ad-theming/SKILL.md`).

## Vulnerability catalog + injection

Adding a vuln = one self-contained YAML in `catalog/vulnerabilities/` (no generator
changes):

```yaml
id: adcs-esc1
severity: critical
attack:   { mitre_attack: [T1649], requires_services: [adcs], intended_path: "..." }
inject:   { type: ansible, playbook: templates/ansible/vulns/adcs_esc1.yml, params: {...} }
neutralized_by: [hardening.controls.adcs_template_hardening, {hardening.baseline: [cis-l2]}]
mitigate: { summary: "..." }
validate: { bloodhound_edge: ADCSESC1, atomic: T1649 }
```

26 entries ship (AD, ADCS, delegation, ACL, OS/service-privesc). `generate` turns
each spec `vulnerabilities[]` id into an idempotent Ansible play targeting the
right host, recording the intended path + reconciliation-derived neutralization
status (`gap-preserved` / `AT RISK` / `clear`) in `lab-manifest.json`. Injected
artifacts are **named and deterministic** (e.g. `svc-sqlreport` with an SPN), not
random picks — see `vuln-injection/SKILL.md`.

## Defensive controls (PREVENT/RESPOND — no SIEM)

`generate` renders `defensive-controls.yml`: the resolved hardening baseline via
`vendor/ansible-lockdown` (with `skip_rules` from the reconciliation), EDR
(Defender AV only), and deception (honey accounts). Only two seed vulns have a
**verified** ansible-lockdown rule mapping (`smb-signing-disabled` ↔ CIS
2.3.8.x/2.3.9.x; `unconstrained-delegation` ↔ RunAsPPL, in the `ngws` profile not
default L1/L2). The rest are conceptual — audited and honestly reported as having
no matching rule rather than guessed. See `defensive-controls/SKILL.md`.

## The lab report (`lab-report.md`)

`generate` writes `generated/<lab>/lab-report.md` — the manifest as
human-readable docs (machines, topology, forest, population, hardening applied
with exact `--tags` + exclusions, EDR, every injected vuln + target + status).
**It contains every generated secret** (domain admin, WinRM account, local admin,
each injection account) and **every population user's name + password** (the whole
population is deterministic Python). So it lives in gitignored `generated/<lab>/`,
never committed. The only thing not knowable ahead of deploy is the honey
accounts' passwords (randomized at deploy time) — query them after deploy via
`ad-inventory`.

### Post-deploy inventory (`forge.py ad-inventory`)

Verification, not discovery — once the lab is reachable (tunnel up):

```bash
python3 scripts/forge.py ad-inventory specs/<lab>.yml   # writes generated/<lab>/ad-inventory.md
```

Queries the live domain (LDAP via `ldap3`; `nxc`/netexec for an NTDS hash dump via
DCSync), confirms it matches the manifest's `population_plans` (flagging anything
missing), and renders every user (NT hash, memberships, tagged `VULN:<id>`/`PRIV`)
and group. NT hashes come from AD live (pass-the-hash usable, crackable with
`hashcat -m 1000`). Same sensitivity as `lab-report.md` — gitignored, re-run
anytime.

## Deploy order: `site.yml`

`generate` writes `site.yml`, importing `ad-topology.yml` → `ad-population.yml` →
`defensive-controls.yml` → `vuln-injection.yml` (in that order — this is what makes
"hardening before vulns" true regardless of who runs `/deploy`). **Run `site.yml`,
not the individual playbooks.**

> **Known gap:** the clean-state snapshot (after vuln-injection, before any attack)
> has no mechanism yet — it needs an `azurerm` snapshot resource or Ansible
> equivalent wired into a `/deploy` orchestrator. Don't assume "reset between
> exercises" works. `site.yml`'s header carries the same note.

## Deploy a lab

One command builds infra + tunnel + AD + hardening + vulns, safe to re-run:

```bash
python3 scripts/forge.py deploy specs/<lab>.yml   # == ./generated/<lab>/deploy.sh
```

When it finishes, `lab-report.md` has every credential + the attack path. You
reach the lab **only** through the WireGuard tunnel `deploy.sh` brings up. Tear
down with `./generated/<lab>/teardown.sh` (or `forge.py teardown`): zero cost.

### Prerequisites (both providers)

- Repo cloned **with submodules** (`vendor/` holds the Ansible roles).
- On the host: `terraform` (>= 1.5), `docker`, `wireguard-tools`, `openssl`,
  `curl`, `python3`. Ansible runs in a container `deploy.sh` starts — you don't
  install it.
- Passwordless sudo for tunnel bring-up:
  ```bash
  echo "$USER ALL=(root) NOPASSWD: /usr/bin/wg, /usr/bin/wg-quick" \
    | sudo tee /etc/sudoers.d/pf-wireguard && sudo chmod 440 /etc/sudoers.d/pf-wireguard
  ```

Nothing account- or host-specific is baked into a lab: credentials come from your
environment at deploy time; `deploy.sh` mints the lab's infra secrets on first run.

### Azure

Install `az`, then log in one of two ways:

```bash
az login && az account set --subscription <sub-id>          # interactive
# or non-interactive — export a service principal:
export ARM_TENANT_ID=<t> ARM_SUBSCRIPTION_ID=<s> ARM_CLIENT_ID=<a> ARM_CLIENT_SECRET=<x>
#   create once: az ad sp create-for-rbac --name pf-deployer --role Contributor --scopes /subscriptions/<sub-id>
```

`./generated/<lab>/deploy.sh` creates its own remote-state storage account and
auto-picks the cheapest available VM size. Optional (no spec edit):
`PF_REGION=<region>`, `PF_VM_SIZE=<sku>`.

### Proxmox

> Fresh host? [`PROXMOX-DEPLOY-RUNBOOK.md`](PROXMOX-DEPLOY-RUNBOOK.md) covers host
> prep (bridges, storage, API token, templates) first.

```bash
export PROXMOX_VE_ENDPOINT="https://pve.example.lan:8006/"
export PROXMOX_VE_API_TOKEN="user@pam!tokenid=xxxx-...."
export PROXMOX_VE_INSECURE=true    # only if the cert is self-signed
```

Token needs rights to create VMs/pools/snippets/firewall rules; `openssh-client`
must be on the host. Then fill the host binding once (the only host-specific part):

```bash
cp generated/<lab>/terraform/proxmox/host.auto.tfvars.example.json \
   generated/<lab>/terraform/proxmox/host.auto.tfvars.json
```

| Key | What to put |
| --- | --- |
| `node_name` | PVE node (`pvesh get /nodes`) |
| `datastore_id` | datastore for VM disks (e.g. `local-lvm`) |
| `snippets_datastore_id` | a datastore with **Snippets** content enabled (often `local`) |
| `mgmt_bridge` / `lab_bridge` | routable bridge for the bastion / isolated bridge for the lab |
| `template_map` | each `os` → the **vm_id** of your Windows template to clone |
| `bastion_template_id` | vm_id of an Ubuntu 22.04+ cloud-init template (qemu-guest-agent) |
| `jumpbox_external_ip`/`_prefix`/`_gateway` | the bastion's address on `mgmt_bridge` |

Windows templates need only **cloudbase-init** (UserDataPlugin enabled); WinRM +
the `ansible` account are set up on first boot. See
[`IMAGES-AND-TEMPLATES.md`](IMAGES-AND-TEMPLATES.md). Then
`./generated/<lab>/deploy.sh` (optional: `PF_TEMPLATE_ID=<vmid>` clones every VM
from one template).

### Different image/template without regenerating

- **Azure:** `PF_OS=windows-server-2022` (stock) or `PF_IMAGE_ID=<resource-id>`
  (your managed image / gallery version).
- **Proxmox:** `PF_TEMPLATE_ID=<vmid>`.

```bash
PF_OS=windows-server-2022 ./generated/<lab>/deploy.sh
```

Swaps only the base image; hardening stays as generated. Full details:
[`IMAGES-AND-TEMPLATES.md`](IMAGES-AND-TEMPLATES.md).

### After deploy

- **Check:** `python3 scripts/forge.py validate specs/<lab>.yml --run` (writes
  `validation-report.md`).
- **Tear down:** `./generated/<lab>/teardown.sh` — destroys everything, verifies
  nothing billable remains.

> **If a step fails:** re-running `deploy.sh` usually clears transient errors.
> [`AZURE-DEPLOY-RUNBOOK.md`](AZURE-DEPLOY-RUNBOOK.md) /
> [`PROXMOX-DEPLOY-RUNBOOK.md`](PROXMOX-DEPLOY-RUNBOOK.md) are the symptom→cause
> references and the manual step-by-step equivalent. AWS is not built yet — Azure
> and Proxmox only.

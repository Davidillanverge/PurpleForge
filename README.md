# PurpleForge

A specification-driven harness that turns a declarative `lab-spec.yml` into
complete automation (Terraform + Ansible + PowerShell) for deploying
**Purple-Team-instrumented Active Directory labs** on **Azure or on-prem Proxmox VE** (AWS on the roadmap) —
including a configurable **defensive stack** (CIS/STIG hardening, Defender AV,
deception) deployed alongside the intentional vulnerabilities.

PurpleForge does not reinvent Windows/AD deployment or endpoint hardening. It
wraps and reuses mature upstream projects, pinned as git submodules in
`vendor/`: **GOAD v3** (IaC + AD engine), **Vulnerable-AD** (vulnerability
primitives), and **ansible-lockdown** (CIS/STIG hardening roles).

See `.claude/agents/README.md` for the agent system and `CLAUDE.md` for the
invariants and deploy order. The deterministic logic lives in `scripts/forge.py`.

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
│                                 # ad-theming, vuln-injection, defensive-controls, purple-validation
├── specs/
│   ├── schema/lab-spec.schema.json
│   └── examples/                # medieval-2dom-azure.yml, corp-espionage-aws.yml, single-dc-azure.yml
├── catalog/
│   ├── vulnerabilities/         # id.yml: attack + inject + detect + neutralized_by + mitigate + validate
│   ├── themes/                  # medieval-kingdom, corporate, space-station: vocabulary + extra_groups
│   ├── machine-profiles/        # (later phase) default OS/sizing per role, currently hardcoded in infra-azure
│   └── defense/
│       ├── profiles/            # none, realistic, hardened
│       ├── edr/                 # per-product: backend_required + implementation notes (only defender-av: false)
│       └── hardening/           # cis-l1/cis-l2/stig/baseline-controls (role_by_os + tags_by_role) +
│                                 # control-cis-rules.yml (VERIFIED control -> concrete CIS rule mappings)
├── templates/
│   ├── terraform/azure/         # VNet/subnets/NSGs/WireGuard bastion (network-topology) +
│   │                             # Windows VMs/WinRM bootstrap (infra-azure); thin wrapper over vendor/GOAD
│   ├── terraform/proxmox/       # on-prem: pool/firewall/VLANs + cloned Windows VMs +
│   │                             # WireGuard bastion (infra-proxmox); bpg/proxmox provider
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

## Create a lab

A lab is a single YAML spec in `specs/`. Either write one by hand starting from
an example in `specs/examples/`, or let the AI `/new-lab` step turn a
plain-English description into a validated spec:

```bash
/new-lab "2 medieval domains, ESC1 + Kerberoasting, Azure, Defender AV + CIS L1"
```

Everything after the spec exists is a plain `forge.py` command — no AI, safe to
run unattended:

```bash
python3 scripts/forge.py generate specs/<lab>.yml          # render Terraform + Ansible + deploy.sh/teardown.sh
python3 scripts/forge.py deploy   specs/<lab>.yml          # build the lab (see "Deploy a lab" below)
python3 scripts/forge.py validate specs/<lab>.yml --run    # check the injected vulns are live and exploitable
python3 scripts/forge.py teardown specs/<lab>.yml          # destroy everything, back to zero cost
```

`generate` writes a **self-contained** `generated/<lab>/` — Terraform, Ansible,
`lab-report.md` (with every credential and the attack path), and a `deploy.sh` /
`teardown.sh`. `generated/` is the **result of running the harness**, not part of
it: it is gitignored and never committed. To share a lab, share its
`specs/<lab>.yml` — determinism guarantees anyone regenerates byte-identical
artifacts with `forge.py generate`. Choose where it runs with `provider: azure`
or `provider: proxmox` in the spec; see [Deploy a lab](#deploy-a-lab).

> **Status:** the full Azure lifecycle (generate → deploy → validate → teardown)
> is deterministic today, and Proxmox generate + deploy work the same way. The
> project stops at PREVENT/RESPOND (hardening + Defender AV) — it does not stand
> up a SIEM — and AWS is still on the roadmap.

## Custom machine images

> Full reference — spec pins, deploy-time `PF_*` overrides, the Azure image
> map/gotchas, and the Proxmox template + first-boot bootstrap — is in
> [`IMAGES-AND-TEMPLATES.md`](IMAGES-AND-TEMPLATES.md). The short version:

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
  profile: realistic                 # none | realistic | hardened
  edr:
    - { product: defender-av, mode: enabled, settings: { asr_rules: audit }, targets: all }
  hardening:
    baseline: cis-l1                 # none | cis-l1 | cis-l2 | stig | baseline-controls
    apply_to: all
    controls: { laps: true, lsa_protection: true, smb_signing: enforce, ldap_signing: enforce, ... }
    intentional_gaps_auto: true      # derive hardening exclusions from each vuln's neutralized_by
  deception: { honey_accounts: 3 }

on_conflict: exclude-control         # warn | exclude-control | fail
```

`profile` fixes sensible defaults (`catalog/defense/profiles/<profile>.yml`);
everything under `edr`/`hardening`/`deception` is a fine-grained override
layered on top.

| Profile | Deploys | For |
|---|---|---|
| `none` | nothing | purely offensive practice |
| `realistic` | Defender AV (ASR audit) + CIS L1 (with intentional gaps) + honey accounts | the most representative mid-size-company scenario |
| `hardened` | CIS L2/STIG + ASR enforce + LAPS + Credential Guard | evasion/hardening stress-testing |

> **Scope:** the harness ships **PREVENT/RESPOND only** — CIS/STIG hardening,
> Microsoft Defender AV, and deception (honey accounts). It does **not** stand up
> a SIEM or ship Sysmon/WEF telemetry; detection engineering (Sigma rules, a SIEM
> back end) is deliberately out of scope for now. Microsoft Defender AV is the
> only supported EDR — every other product needs a management back end this
> project does not build.

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

`lab.theme` + `population` drive a themed, fully deterministic population —
OU tree, users (with passwords), groups, and computers — computed entirely
in Python (`scripts/population.py`) before any deployment happens:

```yaml
lab:      { theme: medieval-kingdom, ... }
population: { users: 300, density: realistic, seed: 1337 }
```

`population.users` is the direct user count; `GroupCount`/`ComputerCount`
scale off it by `density`. `catalog/themes/<theme>.yml`'s vocabulary
(department "house" codes, given/family name pools) feeds the generator
directly, and `random.Random(population.seed)` (offset per domain in a
multi-domain forest) makes the whole plan reproducible. This replaced an
earlier BadBlood-wrapping design — `vendor/BadBlood` stays in the repo
pinned but unused; see `.claude/skills/ad-theming/SKILL.md` for the full
mechanism and why the replacement happened. Theme `extra_groups`
(theme-specific privileged groups) fold directly into the same population
plan, tagged `curated: true`.

```bash
python3 scripts/forge.py generate specs/examples/medieval-2dom-azure.yml
# every user/group/computer/OU is already in lab-manifest.json's population_plans
python3 -c "import json; m=json.load(open('generated/shadow-keep/lab-manifest.json')); print(len(m['population_plans'][0]['users']), 'users')"
```

## Vulnerability catalog

Adding a vulnerability is adding a self-contained YAML file in
`catalog/vulnerabilities/` — no generator code changes required:

```yaml
id: adcs-esc1
severity: critical
attack:   { mitre_attack: [T1649], requires_services: [adcs], intended_path: "..." }
inject:   { type: ansible, playbook: templates/ansible/vulns/adcs_esc1.yml, params: {...} }
neutralized_by: [hardening.controls.adcs_template_hardening, {hardening.baseline: [cis-l2]}]
mitigate: { summary: "..." }
validate: { bloodhound_edge: ADCSESC1, atomic: T1649 }
```

26 entries ship today across the AD, ADCS, delegation, ACL and OS/service-privesc
classes (`kerberoasting`, `adcs-esc1`/`esc4-template-acl`, `unconstrained-`/
`constrained-delegation`, `rbcd-abuse`, `dcsync-acl`, `shadow-credentials`,
`unquoted-service-path`, `mssql-weak-sa`, …) — see `catalog/vulnerabilities/`
for the full set and `vuln-injection/SKILL.md`'s "Adding a vuln" checklist.

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
accounts). **No SIEM or telemetry pipeline ships with this project** — no
Sysmon/WEF/SIEM is stood up; this is PREVENT/RESPOND only, and detection
engineering (Sigma rules + a SIEM back end) is a deliberate future scope.

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
      note: control 'gpp_cpassword_removed' excluded, but no control-cis-rules.yml entry exists for it — no skip_rule derived.
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

**It does show every population user's real name and password** — unlike
BadBlood-era PurpleForge, the whole population is a deterministic Python
computation (`scripts/population.py`), so nothing here is randomized on the
Windows host at deploy time. The one thing still not knowable ahead of
deployment is the honey accounts' passwords, randomized at *deploy time* via
an Ansible `lookup()` plugin — query the live domain for those after
`/deploy`, see `ad-inventory`, next.

## Post-deploy AD inventory (`forge.py ad-inventory`)

`lab-report.md` already documents every population user's plaintext
password ahead of deployment — `ad-inventory` is **verification**, not
discovery: once the lab is actually deployed and reachable (WireGuard
tunnel up),

```bash
python3 scripts/forge.py ad-inventory specs/examples/<lab>.yml
# writes generated/<lab>/ad-inventory.md
```

queries the live domain directly (LDAP via `ldap3` for every user + group +
membership, `nxc`/netexec for an NTDS hash dump via DCSync), confirms the
live domain actually matches `lab-manifest.json`'s `population_plans`
(flagging anything missing — a failed/partial `ad-population.yml` run), and
renders every user (NT hash, group memberships, tagged `VULN:<id>` if it's
one of the injected vulnerability accounts, tagged `PRIV` if it's in a
privileged group) and every group (description, full member list). NT
hashes are pulled here (not from the spec-time report) because they
genuinely are stored in AD and DCSync-recoverable regardless of what this
project computed — directly usable (pass-the-hash) or crackable offline
(`hashcat -m 1000`). Same sensitivity as `lab-report.md` — gitignored, never
commit it, re-run anytime the domain changes (it always reflects current
state, not original intent).

## Deploy order: `site.yml` is the entry point

`generate` also writes `ansible/playbooks/site.yml`, importing
`ad-topology.yml` → `ad-population.yml` → `defensive-controls.yml` →
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

## Deploy a lab

One command builds the whole lab — infrastructure, the WireGuard tunnel, Active
Directory, hardening, and the vulnerabilities — and it is safe to re-run if any
step fails:

```bash
python3 scripts/forge.py deploy specs/<lab>.yml
# exactly the same as running the generated script yourself:
./generated/<lab>/deploy.sh
```

When it finishes, `generated/<lab>/lab-report.md` has every credential and the
attack path. You reach the lab **only** through the WireGuard tunnel `deploy.sh`
brings up — nothing in the lab is exposed to the internet. Tear it all down with
`./generated/<lab>/teardown.sh` (or `forge.py teardown`): back to zero cost.

### What you need (both providers)

- The repo cloned **with submodules** (`git clone --recurse-submodules …`, or
  `git submodule update --init --recursive`) — `vendor/` holds the Ansible roles.
- On the host: `terraform` (>= 1.5), `docker`, `wireguard-tools`, `openssl`,
  `curl`, `python3`. Ansible runs inside a container `deploy.sh` starts for you —
  you do **not** install it.
- Passwordless sudo for the tunnel bring-up:

  ```bash
  echo "$USER ALL=(root) NOPASSWD: /usr/bin/wg, /usr/bin/wg-quick" \
    | sudo tee /etc/sudoers.d/pf-wireguard && sudo chmod 440 /etc/sudoers.d/pf-wireguard
  ```

Nothing account- or host-specific is baked into a lab: credentials come from your
environment at deploy time, and `deploy.sh` mints the lab's own infra secrets on
the first run. The same generated lab deploys on anyone's Azure account or
Proxmox cluster.

### Deploy on Azure

Also install the `az` CLI on the host. Then log in **one** of two ways:

```bash
# A) your own account, interactive:
az login && az account set --subscription <subscription-id>

# B) non-interactive / CI — export a service principal instead of az login:
export ARM_TENANT_ID=<tenant> ARM_SUBSCRIPTION_ID=<sub> \
       ARM_CLIENT_ID=<app-id> ARM_CLIENT_SECRET=<secret>
#   create one once, from an account allowed to grant roles:
#   az ad sp create-for-rbac --name pf-deployer --role Contributor \
#     --scopes /subscriptions/<subscription-id>
```

Deploy:

```bash
./generated/<lab>/deploy.sh
```

`deploy.sh` creates its own remote-state storage account and auto-picks the
cheapest available VM size for the region — you manage neither. Optional, without
editing the spec: `PF_REGION=<region>` to deploy elsewhere, `PF_VM_SIZE=<sku>` to
force a VM size your subscription allows.

### Deploy on Proxmox

> **Fresh Proxmox host (nothing configured yet)?** [`PROXMOX-DEPLOY-RUNBOOK.md`](PROXMOX-DEPLOY-RUNBOOK.md)
> walks through preparing the host itself — network bridges, storage, the
> API token, and building the two required templates — before any of the
> steps below apply.

**1. Point at your Proxmox host** with an API token (never baked into the lab):

```bash
export PROXMOX_VE_ENDPOINT="https://pve.example.lan:8006/"
export PROXMOX_VE_API_TOKEN="user@pam!tokenid=xxxxxxxx-...."
export PROXMOX_VE_INSECURE=true    # only if the PVE cert is self-signed
```

The token needs rights to create VMs, pools, snippets and firewall rules, and
`openssh-client` must be on the host (the deploy reaches the bastion over SSH).

**2. Fill the host binding once** — the only host-specific part. Copy the example
and edit it:

```bash
cp generated/<lab>/terraform/proxmox/host.auto.tfvars.example.json \
   generated/<lab>/terraform/proxmox/host.auto.tfvars.json
```

| Key | What to put |
| --- | --- |
| `node_name` | your PVE node (`pvesh get /nodes`) |
| `datastore_id` | datastore for VM disks, e.g. `local-lvm` |
| `snippets_datastore_id` | a datastore with the **Snippets** content type enabled (often `local`) |
| `mgmt_bridge` / `lab_bridge` | routable bridge for the bastion / isolated bridge for the lab (set both the same if you only have one) |
| `template_map` | each `os` in the lab → the **vm_id** of your Windows template to clone |
| `bastion_template_id` | vm_id of an Ubuntu 22.04+ cloud-init template (with qemu-guest-agent) |
| `jumpbox_external_ip` / `_prefix` / `_gateway` | the bastion's address on `mgmt_bridge` (how you reach WireGuard) |

Your **Windows templates** need only **cloudbase-init** installed (with its
UserDataPlugin enabled). WinRM and the `ansible` account are set up automatically
on first boot — you do **not** prepare a "golden" image. See
[`IMAGES-AND-TEMPLATES.md`](IMAGES-AND-TEMPLATES.md) for a minimal-template
checklist.

**3. Deploy:**

```bash
./generated/<lab>/deploy.sh
```

Optional: `PF_TEMPLATE_ID=<vmid>` clones every VM from one template instead of
the per-OS `template_map`.

### Using a different image or template

Redeploy the same lab on a newer or custom image without editing the spec or
regenerating:

- **Azure:** `PF_OS=windows-server-2022` (a stock image) or
  `PF_IMAGE_ID=<resource-id>` (your own managed image / gallery version).
- **Proxmox:** `PF_TEMPLATE_ID=<vmid>`.

```bash
PF_OS=windows-server-2022 ./generated/<lab>/deploy.sh
```

This swaps only the base image; the hardening baseline stays as generated. Full
details, all variables, and per-machine pins:
[`IMAGES-AND-TEMPLATES.md`](IMAGES-AND-TEMPLATES.md).

### After deploy

- **Check it worked:** `python3 scripts/forge.py validate specs/<lab>.yml --run`
  confirms each vulnerability is applied and exploitable, and writes
  `validation-report.md`. Credentials and the attack path are in
  `generated/<lab>/lab-report.md`.
- **Tear it down:** `./generated/<lab>/teardown.sh` (or `forge.py teardown`)
  destroys everything and verifies nothing billable is left.

> **If a step fails:** the generated `deploy.sh` already encodes the full happy
> path plus retries, so re-running usually clears transient errors.
> [`AZURE-DEPLOY-RUNBOOK.md`](AZURE-DEPLOY-RUNBOOK.md) /
> [`PROXMOX-DEPLOY-RUNBOOK.md`](PROXMOX-DEPLOY-RUNBOOK.md) are the symptom→cause
> references (quota, image-generation mismatches, WinRM/NTLM quirks for Azure;
> host prep, templates, cloudbase-init for Proxmox) and document the manual,
> step-by-step equivalent of what the script does. `infra-aws` is not built
> yet — Azure and Proxmox only today.

# PurpleForge

A spec-driven harness that compiles one declarative `specs/<lab>.yml` into
complete automation (Terraform + Ansible + PowerShell) for deploying isolated,
**Purple-Team-instrumented Active Directory labs** on **Azure, AWS, or on-prem
Proxmox VE**. Every lab ships its **defensive stack**
(CIS/STIG hardening, Defender AV, deception) *alongside* the intentional
vulnerabilities — attack and defense are generated, reconciled, and deployed
together.

It does not reinvent Windows/AD deployment or hardening: it wraps mature
upstream projects pinned as git submodules in `vendor/` — **GOAD v3** (IaC + AD
engine), **Vulnerable-AD** (vulnerability primitives), and **ansible-lockdown**
(CIS/STIG roles).

---

## Objective

Stand up realistic, **safe-by-construction** AD environments for Purple-Team
practice from a single, portable, human-readable spec — and make them
**reproducible**: the same spec always produces the same lab, so a lab can be
shared, versioned, and rebuilt identically on any infrastructure.

The design goals, in priority order:

1. **Reuse, don't reinvent.** Thin generation layers over `vendor/`; never
   re-implement upstream deployment/hardening.
2. **Spec-driven & reproducible.** `specs/<lab>.yml` is the *only* hand-edited
   source. Everything under `generated/<lab>/` is derived, deterministic, and
   gitignored — **the spec alone reproduces the entire lab, byte for byte**,
   secrets included (all are seeded from `population.seed`).
3. **Purple = offense ∧ defense, coupled.** Every catalog vulnerability ships
   `mitigate` + `neutralized_by` + a valid ATT&CK id. A lab is *always* deployed
   with its defensive stack, never the offensive half alone.
4. **Offense and defense are reconciled**, not merely coexisting: before
   generation, hardening is cross-checked against the selected vulnerabilities so
   a control never silently cancels an intended gap.
5. **Secure by construction.** VPN-only access, deny-by-default networking,
   auto-shutdown, and budget alerts are all encoded, not left to the operator.

> **Authorized use only.** Isolated labs, for systems you own or are explicitly
> authorized to test. PurpleForge generates nothing aimed at third-party or
> production systems.

**Scope today:** PREVENT/RESPOND — CIS/STIG hardening, Defender AV, deception.
No SIEM/Sysmon/WEF telemetry; detection engineering is deliberately out of
scope. Azure, AWS, and Proxmox VE are supported.

---

## Capabilities

| Area | What PurpleForge does |
|---|---|
| **Infrastructure as code** | Renders Terraform for Azure (VNet, deny-by-default NSGs, WireGuard bastion, Windows VMs) or Proxmox VE (pool, firewall, VLAN-isolated bridges, cloned VMs, bastion) — a thin wrapper over `vendor/GOAD`. |
| **AD topology** | Multi-domain forests, child domains, and trusts (parent-child / external / forest / shortcut), promoted and joined by GOAD's own Ansible roles. |
| **Themed population** | Fully deterministic OU tree, users (with passwords), groups, computers, and ACL noise — generated in Python (`scripts/population.py`) from a theme's vocabulary and `population.seed`. No BadBlood at runtime. |
| **Vulnerability injection** | 26 catalog vulns (AD, ADCS/ESC, delegation, ACL abuse, OS/service local-privesc) injected as **named, idempotent** artifacts on the correct host, cast onto real population objects — not random picks. |
| **Defensive stack** | CIS L1/L2 or STIG baselines (via `ansible-lockdown`), fixed hardening toggles (LAPS, LSA protection, SMB/LDAP signing, LLMNR/NBT-NS off, Credential Guard, Protected Users), Defender AV (ASR/tamper/network protection), and deception honey accounts. |
| **Reconciliation** | Cross-checks hardening against each vuln's `neutralized_by` and resolves conflicts per `on_conflict` (`warn` / `exclude-control` / `fail`) — so intended gaps survive an otherwise-hardened box. |
| **Attack-chain design** | `independent` mode (each vuln targets its own object) or `ctf` mode (vulns deliberately share a real object, so exploiting one is a prerequisite for the next). |
| **Cost & lifecycle** | Every lab carries `auto_shutdown` + `budget_alert_usd`; `teardown` verifies cost-zero; `reset` rolls back to a clean-state snapshot between exercises. |
| **Validation** | `validate --run` drives the injected vulns live over the tunnel (roasting auto-confirmed with `nxc`; the rest emit a ready-to-run command). `ad-inventory` dumps the live domain (LDAP + DCSync hashes) and checks it against the plan. |
| **Deterministic, no-AI lifecycle** | `generate` → `guardrail` → `deploy` → `validate` → `reset`/`teardown` are pure scripts. AI (skills/agents) only helps *author* a spec; nothing about deployment depends on it. |

---

## Get started

```bash
git clone --recurse-submodules <this-repo>   # or: git submodule update --init --recursive
python3 -m venv .venv && source .venv/bin/activate
pip install -e . -c constraints.txt            # runtime; puts the `forge` command on PATH
# ...or with the dev extras (linters, type-checker, tests):
pip install -e ".[dev]" -c constraints.txt
```

Deps are pinned exactly (`pyproject.toml`) and `constraints.txt` locks the full
transitive closure, so every deployer runs the same renderer — the install side
of invariant #5 (byte-identical artifacts from the same spec+seed).

`forge <command>` works anywhere after the editable install. Without installing,
`python3 -m forge <command>` from the repo root is the exact same entry point.

The full deterministic lifecycle for an existing spec:

```bash
forge from-exercise <layer.json>          # (optional) author specs/<lab>.yml from a BAS exercise's ATT&CK layer
forge lab-spec  specs/<lab>.yml           # validate + reconcile -> lab-manifest.json
forge generate  specs/<lab>.yml           # render Terraform + Ansible + deploy/start/stop/restart/reset/teardown scripts
forge guardrail specs/<lab>.yml           # PASS/FAIL the CLAUDE.md invariants before any spend
forge deploy    specs/<lab>.yml           # build infra + tunnel + AD + hardening + vulns + clean snapshot
forge validate  specs/<lab>.yml --run     # confirm each vuln is applied + exploitable
forge stop      specs/<lab>.yml           # graceful power-off to minimal cost WITHOUT destroying (terraform state untouched)
forge start     specs/<lab>.yml           # power a stopped lab back on + tunnel + verify reachability (no terraform apply)
forge restart   specs/<lab>.yml           # reboot every VM — unstick a hung machine (power reboot, NOT a snapshot rollback)
forge reset     specs/<lab>.yml           # re-run the Ansible phase on the running VMs (restore the spec's logical state)
forge reset     specs/<lab>.yml --snapshot  # ...or roll every VM back to the clean-state snapshot
forge teardown  specs/<lab>.yml           # confirm (type the lab name, or --force) -> destroy to cost-zero + purge local caches
```

Every generated script also runs standalone and takes the lab directory as its
first argument (default: the directory it lives in), e.g.
`./generated/<lab>/start.sh generated/<lab>`. `deploy.sh` writes
`terraform-outputs.json` (`terraform output -json`) and, after bringing up the
tunnel, `connectivity.json` (bastion SSH, WireGuard handshake, WinRM 5986 on every
host); `start.sh` and `reset.sh` re-run the same probe. `PF_CONNECT_TIMEOUT`
(default 900 s) bounds the wait.

```text
script        terraform            VMs                       Ansible
deploy.sh     init + apply         create / start            site.yml + snapshot
start.sh      reads outputs only   start                     —
stop.sh       untouched            graceful shutdown         —
reset.sh      reads outputs only   untouched (must be up)    site.yml again
rollback.sh   untouched            restore clean snapshot    —
teardown.sh   destroy              destroyed                 — (purges local caches/state)
```

`terraform` (>= 1.5) is only needed for `generate … --plan` (a structural dry
run); without it, `generate` renders everything and skips the plan. Full deploy
prerequisites are in [Deploying a lab](#deploying-a-lab-azure--proxmox-ve).

### Working on the harness itself

```bash
pytest                                   # invariant + unit + guardrail + catalog-schema + determinism tests
ruff check . && ruff format --check .    # lint + format
mypy                                     # type-check scripts/
```

Tests own their inputs — they build specs in code with `make_spec()`
(`tests/_helpers.py`) and assert **invariants that hold for any spec** (IP plan
has no collisions, reconciliation excludes/warns correctly, generation is
byte-for-byte deterministic, every catalog entry matches its schema). There are
no committed golden specs to keep in sync.

---

## Lab creation flow

A lab is one YAML file in `specs/`. From description to a deploy-ready lab:

```
     natural language   ──/new-lab────────▶ ┐
  (AI, optional)                             │
     BAS exercise layer ──forge from-exercise▶ specs/<lab>.yml ──forge generate──▶ generated/<lab>/ ──forge deploy──▶ live lab
  (ATT&CK technique list)                    │  (hand-editable)    (deterministic, no AI)            (deterministic, no AI)
     by hand (copy an example) ────────────▶ ┘
```

1. **Author the spec.** Three fronts, all producing the same hand-editable
   `specs/<lab>.yml`:
   - **By hand** from an example.
   - **`/new-lab`** — turn a description into a validated spec:
     ```bash
     /new-lab "2 medieval domains, ESC1 + Kerberoasting, Azure, Defender AV + CIS L1"
     ```
   - **`forge from-exercise`** — the inverse direction: hand it the ATT&CK
     technique list a Breach & Attack Simulation exercise produced (an ATT&CK
     Navigator layer JSON) and it selects the catalog vulnerabilities that
     reproduce those techniques, so the lab is *provably vulnerable to the attack
     that was designed first*:
     ```bash
     forge from-exercise specs/example-exercise.json --name apt-demo --provider azure
     ```
     It routes required services (e.g. ADCS → a member-server) and
     workstation-local-privesc vulns onto the right hosts, forces every selected
     gap open (`intentional_gaps_auto` + `on_conflict: exclude-control`), and
     reports any technique with no catalog coverage (a runtime-only TTP, or a
     precondition no catalog vuln builds yet) rather than dropping it silently.
     See [`specs/README.md`](specs/README.md) for the input format and flags.
     The **`/lab-from-exercise`** command wraps this with the coverage-gap
     judgement, the `lab-spec`/`guardrail` gates, and a human spend gate — the
     exercise-driven twin of `/new-lab`.

   **Example — `/lab-from-exercise` on the bundled sample layer.** The example
   layer mixes catalog-covered techniques with runtime-only TTPs; the command
   authors the spec and tells you exactly what mapped and what did not:
   ```console
   $ forge from-exercise specs/example-exercise.json --name apt-demo
   from-exercise — example-exercise.json: 8 technique(s)
     matched 11 vuln(s):
       - adcs-esc1  <- T1649
       - constrained-delegation (approx)  <- T1558.003
       - dcsync-acl  <- T1003.006
       - esc4-template-acl  <- T1649
       - gpp-cpassword  <- T1552.006
       - kerberoasting  <- T1558.003
       - laps-read-acl (approx)  <- T1552.006
       - passwords-in-description (approx)  <- T1552.006
       - rbcd-abuse (approx)  <- T1558.003
       - unconstrained-delegation  <- T1558.003
       - writable-gpo  <- T1484.001
     3 technique(s) with no catalog coverage (not built into the lab):
       T1566.001, T1059.001, T1071.001          # phishing / PowerShell / C2 — runtime TTPs
   OK: wrote specs/apt-demo.yml (11 vuln(s), 2 machine(s))
     next: forge lab-spec specs/apt-demo.yml
   ```
   The `approx` entries are parent↔sub-technique roll-ups (e.g. the layer's
   `T1552.006` reaching the parent `T1552`'s `laps-read-acl`); `--exact-only`
   keeps just the verbatim matches (5 vulns). Then follow the normal pipeline
   (`forge lab-spec` → `generate` → `deploy`).

   The spec declares: the `lab` (name, theme, provider, region, isolation,
   auto-shutdown, budget), the `forest` (domains + trusts), the `machines`
   (roles, OS, services), the `population` (count, density, **seed**), the
   `vulnerabilities[]`, the `defense` block, and `on_conflict`.
2. **Validate & reconcile** — `forge lab-spec` runs JSON-Schema validation,
   semantic checks (name/IP collisions, trust references, vuln prerequisites),
   resolves the defense profile, assigns the IP plan, estimates cost, and runs
   the hardening ⟷ vulnerability reconciliation. It emits
   `generated/<lab>/lab-manifest.json` — the single artifact every later step
   consumes.
3. **Generate** — `forge generate` renders the whole `generated/<lab>/` tree
   (Terraform, Ansible, `site.yml`, `deploy.sh`/`teardown.sh`/`reset.sh`,
   `lab-report.md`). Deterministic and AI-free.
4. **Guardrail** — `forge guardrail` hard-fails if any machine-checkable
   invariant is violated (isolation, purple coupling, reconciliation recorded,
   lifecycle/state). It gates `deploy`.
5. **Deploy → validate → reset/teardown** — see
   [Deploying a lab](#deploying-a-lab-azure--proxmox-ve).

To share a lab, share its `specs/<lab>.yml`: determinism guarantees the recipient
regenerates byte-identical artifacts (and the same credentials).

---

## Vulnerability creation flow

Adding a vulnerability is **"add one YAML, touch no generator code"**:

1. **Write** `catalog/vulnerabilities/<id>.yml` with the required shape (see
   below). Model it on an existing entry (`kerberoasting.yml`, `adcs-esc1.yml`).
2. **Author the inject primitive** it references — either a `vendor/Vulnerable-AD`
   function or an Ansible task file under `templates/ansible/vulns/<id>.yml`. It
   must create a **named, deterministic, idempotent** artifact.
3. **Validate the shape** against the schema (this is the author-time contract
   for invariant #3 — offense must ship its blue counterpart):
   ```bash
   python3 -c "import yaml,jsonschema,forge; \
     jsonschema.Draft202012Validator(forge.load_vulnerability_schema()).validate(\
       yaml.safe_load(open('catalog/vulnerabilities/<id>.yml'))); print('OK')"
   # or validate the whole catalog:  pytest tests/test_catalog_schema.py
   ```

```yaml
id: adcs-esc1
name: "ADCS ESC1 - enrollee-supplies-subject certificate template"
severity: critical
attack:
  mitre_attack: [T1649]
  requires_services: [adcs]          # or: target_role: workstation (for OS-level vulns)
  intended_path: "..."
inject:
  type: ansible
  playbook: templates/ansible/vulns/adcs-esc1.yml
  params: {}
neutralized_by:                       # MANDATORY — the blue counterpart
  - hardening.controls.adcs_template_hardening
  - { hardening.baseline: [cis-l2] }
mitigate: { summary: "..." }          # MANDATORY
validate: { bloodhound_edge: ADCSESC1, atomic: T1649 }
chain: { target_shape: none }         # none | account | group_scope
```

The `catalog-author` agent researches the ATT&CK id and the upstream primitive,
and enforces the schema for you. `neutralized_by` may reference either a fixed
`hardening.controls.<toggle>` or a `{ hardening.baseline: [...] }` list; the
reconciler uses it to keep the gap open when the baseline would otherwise close
it. `themes/` have their own schema (`catalog/schema/theme.schema.json`) and the
same author-time validation.

---

## Results

Two things constitute a lab, both under version control of the *spec*:

### 1. The spec (`specs/<lab>.yml`) — the portable definition

Hand-edited YAML validated by `specs/schema/lab-spec.schema.json`. **It contains
everything needed to replicate the lab on any infrastructure**: topology,
machines, population parameters, the vulnerability set, the full defensive stack,
and the seed. Because every generated value (down to the domain-admin password)
is a deterministic function of the spec, the spec *is* the lab. Example:

```yaml
lab:
  name: kanto-league
  theme: pokemon
  provider: azure                # azure | proxmox
  region: westeurope
  isolation: vpn-only
  auto_shutdown: "20:00 Europe/Madrid"
  budget_alert_usd: 50
forest:
  - { domain: kanto.local, netbios: KANTO, functional_level: "2016", domain_controllers: 1 }
machines:
  - { role: domain-controller, os: windows-server-2019, domain: kanto.local, count: 1 }
  - { role: member-server,     os: windows-server-2022, domain: kanto.local, count: 1, services: [adcs] }
population: { users: 200, density: realistic, seed: 1337 }
vulnerabilities: [kerberoasting, adcs-esc1, dcsync-acl]
defense:
  profile: realistic
  edr: [{ product: defender-av, mode: enabled, settings: { asr_rules: audit }, targets: all }]
  hardening: { baseline: cis-l1, apply_to: all, intentional_gaps_auto: true }
  deception: { honey_accounts: 3 }
on_conflict: exclude-control
```

### 2. The generated lab (`generated/<lab>/`) — ready to deploy

`forge generate` produces a self-contained, gitignored directory:

| Artifact | What it is |
|---|---|
| `lab-manifest.json` | The resolved plan every step reads: network plan, cost, reconciliation, population, planned vulns, hardening/EDR/deception plans, attack chain. |
| `terraform/<provider>/` | The full infra layer. `terraform.tfvars.json` is secret-free & shareable; the two seed-derived infra secrets sit in the gitignored `secrets.auto.tfvars.json`. |
| `ansible/` | Inventory (`hosts.yml`) + playbooks (`ad-topology`, `ad-population`, `defensive-controls`, `vuln-injection`, `service-provisioning`, `verify`) + `site.yml` (the single ordered entry point) + seed-derived secrets in `inventory/group_vars/all/`. |
| `deploy.sh` / `start.sh` / `stop.sh` / `reset.sh` / `rollback.sh` / `restart.sh` / `teardown.sh` | The deterministic, no-AI lifecycle scripts (deploy, power on, graceful power-off, re-run Ansible, clean-snapshot restore, reboot, confirmed cost-zero teardown). `forge deploy`/`start`/`stop`/`reset`/`restart`/`teardown` are thin wrappers (deploy adds the guardrail gate. |
| `lab-report.md` | Human-readable documentation of the whole lab (see below). |

**The lab report (`lab-report.md`)** is the manifest as prose: machines, network
topology, forest, the *complete* population (every user name + password), all
credentials (domain admin, WinRM, local admin, each injection account),
hardening applied (with exact `--tags` and skip-rule exclusions), EDR,
vulnerabilities + target + neutralization status, and the suggested attack path.
**Every value in it is reproducible from the spec** — running `forge generate`
on the same spec anywhere regenerates the exact same report. Because it holds
secrets, it lives in gitignored `generated/<lab>/` and is never committed. (The
only value *not* in the report is the honey-account passwords, randomized by an
Ansible lookup at deploy time; read them post-deploy via `ad-inventory`.)

---

## Folder structure

```
CLAUDE.md                     # invariant rules + deploy order for any agent in this repo
README.md                     # this file
AZURE-DEPLOY-RUNBOOK.md       # Azure symptom->cause reference + manual step-by-step
PROXMOX-DEPLOY-RUNBOOK.md     # Proxmox host prep + deploy reference
IMAGES-AND-TEMPLATES.md       # image/template requirements and overrides
pyproject.toml                # packaging; the `forge` console script

.claude/
  agents/                     # lab-designer, catalog-author, deploy-operator, purple-validator
  commands/                   # /new-lab /lab-from-exercise /deploy /validate /destroy
  skills/                     # lab-spec, network-topology, infra-azure/proxmox/aws, ad-topology,
                              #   ad-theming, vuln-injection, defensive-controls, purple-validation, ...

specs/
  schema/lab-spec.schema.json # the spec contract
  <lab>.yml                   # your specs (gitignored — they are harness input, kept out of git)

catalog/
  vulnerabilities/            # <id>.yml: attack + inject + neutralized_by + mitigate + validate + chain
  themes/                     # <theme>.yml: vocabulary + extra_groups + honey naming
  defense/
    profiles/                 # none | realistic | hardened (defaults for the defense block)
    edr/                      # defender-av.yml (the only supported EDR)
    hardening/                # cis-l1/-l2/stig baselines + control-cis-rules.yml (verified mappings)
  schema/                     # vulnerability.schema.json + theme.schema.json (author-time contracts)

templates/
  terraform/azure/            # VNet/NSGs/bastion + Windows VMs
  terraform/proxmox/          # pool/firewall/VLANs + cloned VMs + bastion
  ansible/                    # playbooks, vuln task-files, service installers, pf_* roles, inventory
  *.sh.j2                     # deploy/teardown/reset script templates (per provider)
  *.md.j2                     # lab-report / ad-inventory templates

scripts/
  forge/                      # the deterministic core (a Python package — see below)
  population.py               # the deterministic themed-population generator

vendor/                       # version-pinned submodules: GOAD, Vulnerable-AD, ansible-lockdown
tests/                        # the harness test suite
generated/                    # gitignored — per-lab output
```

---

## What each part does

- **`scripts/forge/`** — the deterministic core, a layered Python package (never
  re-implement it in prompts):
  - `core` — paths, constants, `SpecError`, small pure helpers (YAML/schema
    loading, deterministic naming, `generate_password`).
  - `catalog` — vulnerability / theme / hardening / defense loaders (+ the
    catalog schema loaders).
  - `planning` — schema + semantic validation, IP plan, cost, the reconciliation,
    and every *plan* (vuln-injection, hardening, EDR, deception, attack chain,
    `derive_infra_secrets`).
  - `render` — turns those plans into the Terraform/Ansible/report artifacts.
  - `lifecycle` — `deploy` / `teardown` / `destroy` / `reset`.
  - `validate` — live vulnerability validation + `ad-inventory`.
  - `__init__` — the `generate`/`lab-spec`/`guardrail` commands and the CLI.
- **`scripts/population.py`** — the seeded, themed population generator that
  replaced BadBlood: same seed ⇒ same OU tree, users, groups, computers.
- **`catalog/`** — all reusable content. A vuln, theme, hardening baseline, or
  EDR profile is data here; adding one never touches the generator.
- **`templates/`** — the Jinja/Terraform/Ansible sources the renderer fills in.
  Thin wrappers around `vendor/`.
- **`vendor/`** — pinned upstream submodules. Never edited; wrapped from
  `templates/` and the skills.
- **`specs/`** — the only hand-edited source of truth. Your `<lab>.yml` files are
  gitignored (they are harness *input*/output, not source code).
- **`generated/`** — gitignored, regenerable output. Sharing a lab = sharing its
  spec, never this directory.
- **`.claude/`** — the (optional) AI layer that only helps *author* specs and
  catalog content. `skills/` are the deterministic building blocks; `agents/` are
  the design/deploy/validation roles; `commands/` are the slash-command entry
  points. None of it is required to deploy — the generated scripts are.
- **`tests/`** — invariant, unit, guardrail, catalog-schema, and end-to-end
  determinism tests over the deterministic core and the rendered artifacts.

### Core concepts

**The `defense:` block.** Every spec declares its defensive stack next to the
vulnerabilities. `profile` (`none` / `realistic` / `hardened`) sets defaults from
`catalog/defense/profiles/`; `edr` / `hardening` / `deception` override on top.

| Profile | Deploys | For |
|---|---|---|
| `none` | nothing | purely offensive practice |
| `realistic` | Defender AV (ASR audit) + CIS L1 (with gaps) + honey accounts | a representative mid-size company |
| `hardened` | CIS L2/STIG + ASR enforce + LAPS + Credential Guard | evasion / hardening stress-testing |

**Reconciliation (hardening ⟷ vulnerabilities).** Hardening can include the exact
rule that would purge an intended vuln. `lab-spec` cross-references each vuln's
`neutralized_by` against the resolved hardening and resolves per `on_conflict`:
`exclude-control` (recommended, with `intentional_gaps_auto: true`) drops just
the conflicting rule and keeps the rest of the baseline; `warn` applies hardening
and lists what might get neutralized; `fail` stops generation. Only two vulns
have a *verified* ansible-lockdown skip-rule mapping today; the rest are honestly
reported as conceptual rather than guessed.

**Theming & population.** `lab.theme` + `population` drive a fully deterministic
population computed before any deploy. `population.users` is the user count;
groups/computers scale off it by `density`; the theme's vocabulary feeds the
generator and `population.seed` makes every name/password/OU reproducible.

**Deploy order (`site.yml`).** `generate` writes `site.yml` importing
`ad-topology` → `ad-population` → `defensive-controls` → `vuln-injection` in that
order, so hardening always lands before the gaps regardless of who runs it. The
clean-state snapshot is taken as the *last* deploy step (after vulns, before any
attack); `forge reset --snapshot` restores it.

> The **clean-state snapshot** step has now run against a live AWS deploy
> (`snapshot_clean` created one AMI per Windows host). `forge reset --snapshot` and
> `verify.yml` are still rendered from the documented procedures but have not yet
> been exercised live — treat their first run with that caution.

---

## Deploying a lab (Azure & Proxmox VE)

One command builds infra + tunnel + AD + hardening + vulns + clean snapshot, and
is safe to re-run:

```bash
forge deploy specs/<lab>.yml            # == ./generated/<lab>/deploy.sh, behind the guardrail gate
```

You reach the lab **only** through the WireGuard tunnel `deploy.sh` brings up — no
lab host ever has a public IP or inbound RDP/WinRM. When it finishes,
`lab-report.md` has every credential and the attack path. Between exercises,
`forge reset` re-runs the Ansible phase on the running VMs (`--snapshot` rolls every
VM back to the clean-state snapshot instead); `forge stop`/`forge start` pause and
resume without touching Terraform; when finished, `forge teardown` (confirm by
typing the lab name, or `--force`) destroys everything and verifies cost-zero.

### Prerequisites (both providers)

- Repo cloned **with submodules** (`vendor/` holds the Ansible roles).
- On the deploy host: `terraform` (>= 1.5), `docker`, `wireguard-tools`,
  `openssl`, `curl`, `python3`, and `nxc`/netexec (for `validate`/`ad-inventory`).
  Ansible itself runs in a container `deploy.sh` starts — you don't install it.
  `pip install -r scripts/requirements.txt` for the Python deps (`ldap3`).
- Passwordless sudo for tunnel bring-up:
  ```bash
  echo "$USER ALL=(root) NOPASSWD: /usr/bin/wg, /usr/bin/wg-quick" \
    | sudo tee /etc/sudoers.d/pf-wireguard && sudo chmod 440 /etc/sudoers.d/pf-wireguard
  ```

Nothing account- or host-specific is baked into a lab: cloud credentials come
from your environment at deploy time, and **every lab secret is derived from the
spec's seed** — `deploy.sh` mints nothing, it just deploys what `generate`
produced.

### Azure

Install the `az` CLI and authenticate one of two ways:

```bash
az login && az account set --subscription <sub-id>          # interactive
# or non-interactive — export a service principal:
export ARM_TENANT_ID=<t> ARM_SUBSCRIPTION_ID=<s> ARM_CLIENT_ID=<a> ARM_CLIENT_SECRET=<x>
#   create once: az ad sp create-for-rbac --name pf-deployer --role Contributor \
#                  --scopes /subscriptions/<sub-id>
```

Requirements & behavior:

- The service principal / user needs **Contributor** on the target subscription
  (it creates a resource group, VNet, NSGs, VMs, and a storage account).
- `deploy.sh` creates its own **remote-state storage account** (Terraform state
  is never local on Azure — invariant #4) and **auto-picks the cheapest VM size**
  your subscription actually offers in the region (the #1 deploy blocker — a
  region/quota-invalid SKU — is handled for you). On the very first deploy of a
  new subscription, run it with the Azure MCP available so quota/pricing can be
  cross-checked; after that the chosen size is baked into `sizes.auto.tfvars.json`.
- Windows **evaluation images** from the marketplace expire ~180 days after
  install — plan a redeploy or apply a retail license before then.
- Optional overrides (no spec edit): `PF_REGION=<region>`, `PF_VM_SIZE=<sku>`,
  `PF_TFSTATE_RG=<rg>`, and for images `PF_OS=windows-server-2022` or
  `PF_IMAGE_ID=<resource-id>` (a managed image / gallery version).

> Troubleshooting: [`AZURE-DEPLOY-RUNBOOK.md`](AZURE-DEPLOY-RUNBOOK.md) is the
> symptom→cause reference and the manual step-by-step equivalent.

### Proxmox VE

> Fresh host? [`PROXMOX-DEPLOY-RUNBOOK.md`](PROXMOX-DEPLOY-RUNBOOK.md) covers host
> prep (bridges, storage, API token, templates) first.

Export the API connection (the token needs rights to create VMs, pools,
snippets, and firewall rules; `openssh-client` must be on the host):

```bash
export PROXMOX_VE_ENDPOINT="https://pve.example.lan:8006/"
export PROXMOX_VE_API_TOKEN="user@pam!tokenid=xxxx-...."
export PROXMOX_VE_INSECURE=true    # only if the PVE cert is self-signed
```

Then fill the **one host-specific file** (everything else is spec-derived):

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
| `jumpbox_external_ip` / `_prefix` / `_gateway` | the bastion's address on `mgmt_bridge` |

Windows templates need only **cloudbase-init** (with UserDataPlugin enabled)
baked in — WinRM and the `ansible` account are bootstrapped on first boot. See
[`IMAGES-AND-TEMPLATES.md`](IMAGES-AND-TEMPLATES.md). Then run
`./generated/<lab>/deploy.sh` (optional: `PF_TEMPLATE_ID=<vmid>` clones every VM
from one template).

Note: Proxmox deliberately uses a **local** Terraform state backend (no on-prem
object store to mint per-deployer) — a documented relaxation of the remote-state
invariant, surfaced as a REVIEW note by the guardrail rather than passing
silently.

### After deploy

```bash
forge validate specs/<lab>.yml --run     # writes validation-report.md (applied + exploitable)
forge ad-inventory specs/<lab>.yml       # writes ad-inventory.md (live users/groups + NT hashes)
forge reset specs/<lab>.yml              # re-run Ansible to restore the spec's state between exercises
forge reset specs/<lab>.yml --snapshot   # ...or roll back to the clean-state snapshot
forge teardown specs/<lab>.yml           # confirm, destroy everything, verify nothing billable remains
```

> **If a step fails:** re-running `deploy.sh` usually clears transient errors.
> The runbooks above are the manual, symptom→cause equivalents — one per
> provider (Azure, AWS, Proxmox).

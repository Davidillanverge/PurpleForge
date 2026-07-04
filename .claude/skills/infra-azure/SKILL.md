---
name: infra-azure
description: >
  Renders the Azure compute layer for a lab: Windows VMs (DC/member-server/
  workstation) sized and imaged per role, WinRM bootstrap, and the
  terraform.tfvars.json that ties it all to lab-manifest.json. Thin wrapper
  reusing vendor/GOAD's proven azurerm_windows_virtual_machine +
  CustomScriptExtension pattern — does not touch networking (that's
  network-topology's job) or AD promotion (that's ad-topology's job, in
  Ansible, after `terraform apply`).
---

# infra-azure

## When to use this skill

- During `/generate`, after `network-topology` has defined
  `templates/terraform/azure/{network,bastion}.tf` (or, in practice today,
  once — they live in the same `generated/<lab>/terraform/azure/` module;
  see below) and the lab's `lab.provider` is `azure`.

## Division of responsibility inside `templates/terraform/azure/`

All Azure `.tf` files live in one Terraform root module
(`templates/terraform/azure/`, copied verbatim into
`generated/<lab>/terraform/azure/` by `scripts/forge.py generate`) — Terraform
has no submodule boundary here, but the *authoring* responsibility is split:

| File | Owned by | Content |
|---|---|---|
| `versions.tf`, `main.tf` | infra-azure | provider/version pins, resource group |
| `network.tf`, `bastion.tf`, `cloudinit/` | network-topology | VNet/subnets/NSGs, WireGuard bastion |
| `windows.tf` | infra-azure | Windows VMs, NICs (private-IP-only), WinRM bootstrap |
| `outputs.tf` | shared | whichever skill added the resource owns its output |
| `variables.tf` | shared | one flat variable set consumed by both |

Don't duplicate a resource across files or skills — if you need a new input,
add the variable once in `variables.tf` and wire `scripts/forge.py`'s
`terraform.tfvars.json` emission to populate it.

## What it generates

- **`windows.tf`**: one `azurerm_windows_virtual_machine` + one
  `azurerm_network_interface` (private IP only — never
  `public_ip_address_id`) + one `azurerm_virtual_machine_extension`
  (`CustomScriptExtension`) per flattened machine instance in
  `lab-manifest.json.network_plan.domains.*.hosts`. The NIC's `subnet_id`
  points at the `azurerm_subnet.domain[<domain>]` that `network-topology`
  defined — `infra-azure` never creates its own subnets.
- **OS → image mapping** (`local.os_image_map` in `windows.tf`): maps the
  schema's `machines[].os` enum to `publisher`/`offer`/`sku`, following
  `vendor/GOAD/ad/GOAD/providers/azure/windows.tf`'s naming convention
  (`MicrosoftWindowsServer` / `WindowsServer` / `"2019-Datacenter"`, etc).
  **The 2022/2025 server SKUs are still best-effort** — GOAD's own file
  carries the same caveat: verify with
  `az vm image list --publisher <p> --offer <o> --all -o table` before a real
  deploy, since Azure marketplace SKU names/availability drift over time.
  `windows-11-23h2` is **not** best-effort — it deliberately maps to the
  `win11-23h2-avd` plan, not `win11-23h2-pro`, verified against a real deploy
  (see "Client-OS images" below for why).
- **Client-OS images (Windows 10/11) need a marketplace agreement.**
  `windows.tf` has an `azurerm_marketplace_agreement.client_os` resource,
  `for_each`-ed over whichever `MicrosoftWindowsDesktop` os values a machine
  in the spec actually uses, with every `azurerm_windows_virtual_machine`
  `depends_on` it. Verified on a real deploy: without accepting this
  agreement, VM creation fails with `PlatformImageNotFound` (a 404, not a
  clearer "terms not accepted" error) — Azure hides marketplace image
  versions from a subscription that hasn't accepted the plan's terms, even
  for first-party Microsoft offers. Also verified: do **not** add a `plan {}`
  block to the VM resource for these — once the agreement is accepted, Azure
  rejects one outright (`ResourcePurchaseValidationFailed: ... doesn't
  require plan information`). And specifically for `windows-11-23h2`:
  `MicrosoftWindowsDesktop/Windows-11/win11-23h2-pro` has **zero published
  image versions** in every region checked (northeurope, westeurope, eastus,
  westus2, francecentral, germanywestcentral, uksouth, switzerlandnorth,
  swedencentral) regardless of agreement acceptance — standalone Windows 11
  client OS isn't offered as a plain IaaS image outside Azure Virtual
  Desktop/Windows 365 or a Visual Studio subscription benefit. `win11-23h2-avd`
  is the same OS build and the only win11-23h2 plan with real image versions;
  it deploys as an ordinary standalone VM (no AVD host pool involved).
  `windows-10-22h2` uses the Gen2 `win10-22h2-pro-g2` SKU — the Gen1
  `win10-22h2-pro` cannot boot a Gen2-only VM size (Fasv7 etc.). Note
  `windows-server-2016`'s image is SCSI-only (no NVMe), so it cannot run on
  the NVMe-only Fasv7/Dsv7/Esv7 sizes some restricted subscriptions offer —
  pick 2019+ there.
- **Custom images** (`machines[].image_id`): overrides the marketplace
  lookup above for that machine group — a full resource ID for either a
  managed image (`.../Microsoft.Compute/images/<name>`) or a Shared Image
  Gallery version (`.../Microsoft.Compute/galleries/<gallery>/images/<def>/versions/<ver>`).
  For a golden workstation image with an EDR agent already baked in, set it
  on that `machines[]` entry; `os` is still required alongside it — it still
  determines which ansible-lockdown role/OS-specific Ansible behavior
  applies downstream, independent of which image backs the VM.
  `windows.tf` uses a `dynamic "source_image_reference"` block gated on
  `image_id == null`, since `azurerm_windows_virtual_machine`'s
  `source_image_id` and `source_image_reference` are mutually exclusive —
  don't set both directly, that's what the dynamic block is for.
  AWS AMI support for the equivalent field doesn't exist yet (no
  infra-aws) — the schema field is named provider-agnostically
  (`image_id`, not `azure_image_id`) so it can be reused as-is when that
  lands.
- **Role → size mapping** (`local.size_map`): `Standard_B2s` for
  domain-controller/workstation, `Standard_B2ms` for member-server (matches
  GOAD's own `Standard_B2s`/`Standard_B2ms` comments in
  `ad/GOAD/providers/azure/windows.tf`). **Some subscriptions (free/trial/
  sponsored) block the entire B-series family** with a persistent
  `NotAvailableForSubscription` restriction in every mainstream region —
  verified on a real deploy where B1s/B2s/B2ms were rejected everywhere
  except a handful of extended-zone regions, while `Standard_D2s_v3` worked
  normally. When that happens, don't hand-edit the hardcoded defaults (they're
  the right cost-optimized choice for a normal subscription) — set
  `var.vm_size_overrides` (a `map(string)` keyed by role, merged over
  `local.size_map`) and `var.bastion_size` in `terraform.tfvars.json` instead.
  Also check the subscription's actual **regional core quota**
  (`Microsoft.Compute/locations/<region>/usages`, `name.value == "cores"`)
  before deploying — a lab this size needs roughly 2 vCPUs × (number of
  machines + 1 bastion). **Correction from an earlier version of this note,
  disproven on a real deploy**: a low total-regional-vCPU quota does NOT
  necessarily mean only a quota increase or a different subscription fixes
  it. `Microsoft.Compute/skus`' `restrictions[]` varies by *region*, not just
  by subscription — a subscription with the same 4-vCPU cap in every region
  can still have an unrestricted 1-vCPU SKU in one region (e.g.
  `Standard_F1as_v7`, 1 vCPU/4GB, confirmed unrestricted in `eastus` on a
  subscription where every 1-vCPU B/A-series SKU was restricted in
  `swedencentral`), letting a 4-host lab (bastion+DC+member-server+
  workstation) fit in a 4-vCPU budget after all. Before concluding a quota
  increase is the only option: query `Microsoft.Compute/skus` across a
  handful of regions for `vCPUs == 1` entries with an empty `restrictions[]`
  (the `az vm`/`az network` CLI subcommands may themselves be broken in some
  environments with an unrelated `KeyError: 'disks'` command-loading bug —
  use `az rest --method get` against the ARM REST API directly instead, it
  doesn't hit that code path). If you do switch region/size this way, also
  check the OS image's Hypervisor Generation matches the new size — see the
  Gen2 note below, hit on the very deploy that found this SKU.
- **`windows-server-2022`/`-2019`/`-2016`/`-2025` marketplace images and
  Hypervisor Generation**: `local.os_image_map`'s plain `"<year>-Datacenter"`
  SKUs are Gen1-only. Newer VM size families (confirmed: `Fasv7`; likely any
  size introduced after Gen2 became the default, e.g. most `v5`/`v6`/`v7`
  families) are Gen2-only and reject them outright at VM creation with `"The
  selected VM size 'X' cannot boot Hypervisor Generation '1'"`
  (https://aka.ms/azuregen2vm) — not a quota/capacity error, a hard
  incompatibility. Fixed by mapping every entry to its Gen2 SKU (Gen2 images
  run on both Gen1- and Gen2-capable sizes, so this is a strict widening, not
  a narrowing, of which `vm_size_overrides` values work) — **but the Gen2
  suffix is NOT the same string across versions**, verified on a real deploy
  after the first fix (2022 only) didn't catch 2016: `2016`/`2019` use
  `-gensecond` (`"2016-datacenter-gensecond"`), `2022`/`2025` use `-g2`
  (`"2022-datacenter-g2"`). If you add another OS to `os_image_map`, list the
  real SKUs first rather than guessing the pattern:
  `az rest --method get --url "https://management.azure.com/subscriptions/
  <sub>/providers/Microsoft.Compute/locations/<region>/publishers/
  MicrosoftWindowsServer/artifacttypes/vmimage/offers/WindowsServer/skus
  ?api-version=2023-07-03"` (not `az vm image list` — broken command-loading
  path in some environments, same as elsewhere in this file).
- **Disk controller type is a SEPARATE compatibility axis from Hypervisor
  Generation — fixing Gen2 doesn't guarantee a VM size actually boots.**
  Verified on a real deploy: `Standard_F1as_v7` (Gen2, used to fit a low
  vCPU quota — see the quota note above) rejected the Gen2
  `2016-datacenter-gensecond` image outright with `"The VM size
  'Standard_F1as_v7' cannot boot with OS image or disk ... check disk
  controller types"` — every `Fsv7`-family size's `DiskControllerTypes`
  capability is `NVMe` *only* (no SCSI fallback), and Windows Server 2016's
  image doesn't support NVMe regardless of which SKU variant you pick.
  `Microsoft.Compute/skus`' `capabilities[].DiskControllerTypes` (`NVMe`,
  or absent — absent means classic/SCSI-only, not "any") tells you this
  before you hit the error; check it alongside `HyperVGenerations` and
  `restrictions[]` when picking a size for an older OS. When no
  NVMe-capable size's disk controller matches the OS image, override just
  that role in `var.vm_size_overrides` to a different unrestricted 1-vCPU
  size — `Standard_DC1s_v3` (a confidential-compute series VM, but usable as
  an ordinary VM without opting into confidential-compute features) is one
  such SCSI-compatible option, confirmed working for a `windows-server-2016`
  domain controller in `eastus` on the same subscription where every
  `F*v7` size failed for it.
- **WinRM bootstrap**: reuses Ansible's own
  `ConfigureRemotingForAnsible.ps1` via `CustomScriptExtension`, exactly as
  `vendor/GOAD/template/provider/azure/windows.tf` does. It creates a
  dedicated local `ansible` automation account distinct from
  `admin_username`/`admin_password` (the interactive local administrator) —
  **do not collapse these into one account**: an earlier draft of this
  template reused `admin_username` for both, which would have collided with
  the account already created at VM provisioning time. Password for the
  `ansible` account is `var.ansible_password`, generated per-lab like
  `admin_password`.

## Generating `terraform.tfvars.json`

`scripts/forge.py generate <lab>` (see its own docstring) reads
`generated/<lab>/lab-manifest.json` and writes
`generated/<lab>/terraform/azure/terraform.tfvars.json` with:
`lab_name`, `location` (from `lab.region`), `supernet`/`management_cidr`/
`jumpbox_private_ip`/`domains` (from `network_plan`), `machines` (flattened
from `network_plan.domains.*.hosts`, each assigned a name — see
`ad-topology`'s naming convention), and freshly generated
`admin_password`/`ansible_password` (random, written only to
`generated/<lab>/`, which is gitignored — never to the spec or the catalog).
It also writes `backend.hcl` (see `versions.tf`'s partial `backend "azurerm"
{}` block — CLAUDE.md invariant #4 requires remote state with locking, so
`versions.tf` never falls back to local state).

## Remote state bootstrap (one-time, per Azure subscription)

`versions.tf` declares a partial backend — `terraform init` needs
`-backend-config=backend.hcl` (which `render_backend_config` in
`scripts/forge.py` generates) to actually configure it, and that config
points at a storage account that must already exist. This is the standard
chicken-and-egg of remote Terraform state: the backend isn't self-hosting.
One shared storage account holds every lab's state, one blob key per lab
(`backend.hcl`'s `key = "<lab.name>.tfstate"`) — not a storage account per
lab (names must be globally unique in Azure; provisioning one per lab would
be wasteful). Bootstrap once:

```bash
az group create -n purpleforge-tfstate-rg -l westeurope
az storage account create -n <globally-unique-name> -g purpleforge-tfstate-rg -l westeurope --sku Standard_LRS
az storage container create -n tfstate --account-name <globally-unique-name>
```

Then edit the generated `backend.hcl`'s `storage_account_name` to match (the
generated placeholder, `purpleforgetfstate`, will not be available — Azure
storage account names are a global namespace) before running
`terraform init -backend-config=backend.hcl` for real. `-backend=false`
(below) is for structural validation only and must never be how a real lab
is deployed.

## Troubleshooting a real `apply` (learned from a live deploy, not theory)

- **`terraform plan`/`apply` hangs for 10+ minutes with no output, then
  eventually "Error: Plugin did not respond".** This is `ConfigureProvider`
  walking ~60 resource-provider namespaces before the first resource op —
  `versions.tf`'s `provider "azurerm"` block now sets
  `skip_provider_registration = true` specifically to prevent this (fixed;
  if you're on an older `generated/<lab>/` predating this, regenerate rather
  than hand-patch). If it still hangs, the actual resource providers this
  module needs (`Microsoft.Storage`, `Microsoft.Compute`, `Microsoft.Network`)
  may not be registered on the subscription yet —
  `az provider register --namespace Microsoft.Compute` (etc) and wait for
  `registrationState: Registered` before retrying.
- **A region rejects everything with "The selected region is currently not
  accepting new customers"**, or specific VM sizes fail with `SkuNotAvailable`
  / `Capacity Restrictions`, or you hit `OperationNotAllowed: ... exceeding
  approved Total Regional Cores quota`. These are subscription/region-specific
  capacity or eligibility limits, not a bug in this module — check
  `Microsoft.Compute/locations/<region>/usages` (cores) and
  `Microsoft.Compute/skus` (per-size `restrictions[].reasonCode`) for the
  target subscription *before* picking a region/size, rather than discovering
  it mid-`apply`. See the size_map note above for the `vm_size_overrides`
  escape hatch.
- **`terraform apply` errors with "Provider produced inconsistent result
  after apply: ... Root object was present, but now absent" for a resource
  that actually exists in Azure**, or a later `plan`/`apply` claims a
  just-created resource needs to be re-created ("already exists... needs to
  be imported"). This is Azure ARM read-after-write lag (the GET right after
  a PUT briefly 404s) surfacing as a Terraform provider bug, not real drift —
  verified repeatedly on one subscription/region during a live deploy,
  including on `azurerm_virtual_network`, `azurerm_network_security_group`,
  and `azurerm_network_interface`. Recovery: `terraform import <address>
  <azure-resource-id>` the specific resource(s) Terraform dropped from state
  (their real IDs follow the standard
  `/subscriptions/<sub>/resourceGroups/<rg>/providers/<type>/<name>` shape),
  then re-plan with `-refresh=false` to avoid re-triggering the same flaky
  read before applying the remaining real changes. If `terraform import`
  itself errors on an unrelated output (e.g. one that indexes
  `var.machines` by name across all machines), temporarily comment out that
  output, import, then restore it — the output's own resources don't need to
  exist yet for the import of something else to succeed.

## Testing this skill

```bash
cd generated/<lab>/terraform/azure && terraform init -backend=false && terraform validate && terraform plan
```

No cloud credentials are needed for `validate`; `plan` needs
`az login`/`ARM_*` credentials configured — if those aren't available,
`terraform validate` is the bar for this skill's own correctness, and a
`terraform plan` dry run (when credentials exist) is the bar for the overall
`/generate --dry-run` acceptance criterion.

`machines[].image_id` specifically was verified only up to `validate`
passing (confirms the `optional(string)` type and the `dynamic
"source_image_reference"` gating are structurally sound) plus a tfvars
inspection (`python3 -c "import json; ..."` on
`terraform.tfvars.json['machines']`) confirming `image_id` resolves to the
real resource ID string for the machine group it was set on and `null` for
every other one. Without real credentials, `plan` can't get far enough to
show which of `source_image_id`/`source_image_reference` Terraform actually
picked for a given VM — every `plan` in this repo's testing stops at the
provider-auth error before reaching any `azurerm_windows_virtual_machine`
resource at all (only the credential-independent `tls_private_key.bastion_ssh`
ever shows). Re-verify with a real `plan`/`apply` against a subscription
that actually has the referenced image before trusting it further.

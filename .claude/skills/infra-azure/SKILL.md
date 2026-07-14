---
name: infra-azure
description: >
  Renders the Azure compute layer for a lab: Windows VMs (DC/member-server/
  workstation) sized and imaged per role, WinRM bootstrap, and the
  terraform.tfvars.json tying it to lab-manifest.json. Thin wrapper reusing
  vendor/GOAD's azurerm_windows_virtual_machine + CustomScriptExtension pattern —
  doesn't touch networking (network-topology) or AD promotion (ad-topology).
---

# infra-azure

## When to use

- `/generate`, after `network-topology` defined `{network,bastion}.tf`, when
  `lab.provider` is `azure`. All Azure `.tf` live in one root module
  (`templates/terraform/azure/`, copied verbatim to `generated/<lab>/`).

## File ownership (one module, split authoring)

| File | Owner | Content |
|---|---|---|
| `versions.tf`, `main.tf` | infra-azure | provider pins, resource group |
| `network.tf`, `bastion.tf`, `cloudinit/` | network-topology | VNet/subnets/NSGs, bastion |
| `windows.tf` | infra-azure | Windows VMs, private-only NICs, WinRM bootstrap |
| `outputs.tf`, `variables.tf` | shared | whoever adds a resource owns its output; one flat var set |

New input → add the variable once in `variables.tf` and wire `forge.py`'s
`terraform.tfvars.json` emission. Don't duplicate a resource across files.

## What `windows.tf` generates

Per machine in `network_plan.domains.*.hosts`: one
`azurerm_windows_virtual_machine` + one NIC (private IP only, never
`public_ip_address_id`) + one `CustomScriptExtension`. NIC `subnet_id` → the
subnet network-topology defined (infra-azure never makes subnets).

- **OS → image** (`local.os_image_map`): `machines[].os` → publisher/offer/sku,
  following GOAD's naming. 2022/2025 server SKUs are **best-effort** — verify
  with `az vm image list --publisher <p> --offer <o> --all -o table` before a
  real deploy (marketplace names drift).
- **Hypervisor Generation**: plain `"<year>-Datacenter"` SKUs are Gen1-only;
  Gen2-only size families (`Fasv7`, most v5/v6/v7) reject them with `"cannot boot
  Hypervisor Generation '1'"`. Every entry maps to its Gen2 SKU (runs on both) —
  **but the suffix differs**: `2016`/`2019` use `-gensecond`, `2022`/`2025` use
  `-g2`. Adding an OS? List real SKUs first via `az rest` (not `az vm image list`
  — broken command-loading in some environments):
  `.../locations/<region>/publishers/MicrosoftWindowsServer/artifacttypes/vmimage/offers/WindowsServer/skus?api-version=2023-07-03`.
- **Disk controller is a SEPARATE axis from Gen**: `F*v7` sizes are `NVMe`-only,
  and `windows-server-2016`'s image has no NVMe support → `"cannot boot with OS
  image or disk ... check disk controller types"`. Check
  `Microsoft.Compute/skus` `capabilities.DiskControllerTypes` (absent = SCSI-only)
  alongside `HyperVGenerations`/`restrictions`. For an old OS on NVMe-only, set
  `vm_size_overrides` for that role to a SCSI 1-vCPU size — `Standard_DC1s_v3`
  (confidential-compute series, usable as an ordinary VM) works for a 2016 DC.
- **Client-OS images (Win 10/11) need a marketplace agreement.** `windows.tf` has
  `azurerm_marketplace_agreement.client_os` `for_each`-ed over the
  `MicrosoftWindowsDesktop` os values used, with every VM `depends_on` it. Without
  it: `PlatformImageNotFound` (a 404). Do NOT add a `plan {}` block once accepted
  (`ResourcePurchaseValidationFailed`). `windows-11-23h2` maps to `win11-23h2-avd`
  (not `-pro`: `-pro` has ZERO published versions anywhere; `-avd` is the same
  build, deploys as an ordinary VM). `windows-10-22h2` uses Gen2 `win10-22h2-pro-g2`.
- **Custom images** (`machines[].image_id`): overrides the marketplace lookup — a
  managed-image or SIG-version resource ID (e.g. a golden EDR-baked workstation).
  `os` stays required (selects the hardening role). `windows.tf` gates a
  `dynamic "source_image_reference"` on `image_id == null` (the two source fields
  are mutually exclusive — don't set both). Field is provider-agnostic for a
  future AWS AMI.
- **Role → size** (`local.size_map`): `Standard_B2s` DC/workstation, `B2ms`
  member-server (GOAD's choice). **Some subscriptions block the whole B-series**
  (`NotAvailableForSubscription`). Don't hand-edit the defaults — set
  `var.vm_size_overrides` (map by role, merged over `size_map`) + `var.bastion_size`
  in `terraform.tfvars.json`. Check regional core quota
  (`Microsoft.Compute/locations/<region>/usages`, `cores`) first; ~2 vCPU × (VMs +
  bastion). A low total-vCPU cap isn't a dead end: `restrictions[]` vary by
  *region*, so a 1-vCPU SKU can be unrestricted in one region (e.g.
  `Standard_F1as_v7` in eastus) letting a 4-host lab fit a 4-vCPU budget. Query
  `Microsoft.Compute/skus` for `vCPUs==1` with empty `restrictions[]` across a few
  regions via `az rest` (the `az vm`/`az network` CLI can hit a `KeyError: 'disks'`
  bug — use the REST API). Match the OS image's Hypervisor Gen to the new size.
- **WinRM bootstrap**: reuses `ConfigureRemotingForAnsible.ps1` via
  `CustomScriptExtension` (like GOAD). Creates a dedicated local `ansible` account
  distinct from `admin_username`/`admin_password` — **don't collapse them** (an
  earlier draft did, colliding with the provisioning-time account). Password =
  `var.ansible_password`, generated per-lab.

## `terraform.tfvars.json` + remote state

`forge.py generate <lab>` reads `lab-manifest.json` and writes
`terraform.tfvars.json` (`lab_name`, `location`, network_plan fields, flattened
`machines`, generated `admin_password`/`ansible_password` — gitignored) + a
`backend.hcl`. `versions.tf` declares a partial `backend "azurerm" {}` (invariant
#4: no local-state fallback), so `terraform init` needs
`-backend-config=backend.hcl` pointing at a storage account that must already
exist. One shared account holds every lab's state (one blob key per lab); names
are globally unique so it's not per-lab. Bootstrap once:

```bash
az group create -n purpleforge-tfstate-rg -l westeurope
az storage account create -n <globally-unique> -g purpleforge-tfstate-rg -l westeurope --sku Standard_LRS
az storage container create -n tfstate --account-name <globally-unique>
```

Then edit `backend.hcl`'s `storage_account_name` (the placeholder
`purpleforgetfstate` won't be available). `-backend=false` is for structural
validation only, never a real deploy.

## Live `apply` gotchas

- **`plan`/`apply` hangs 10+ min then "Plugin did not respond"** — provider
  walking ~60 RP namespaces. `versions.tf` sets `skip_provider_registration =
  true` (fixed; regenerate an old lab). Still hangs? Register
  `Microsoft.Storage`/`Compute`/`Network` (`az provider register --namespace ...`,
  wait for `Registered`).
- **Region "not accepting new customers" / `SkuNotAvailable` / `exceeding
  approved Total Regional Cores`** — subscription/region limits, not a bug. Check
  `usages` (cores) + `skus` (`restrictions[].reasonCode`) before picking. Escape
  hatch: `vm_size_overrides`.
- **"Provider produced inconsistent result ... Root object ... now absent" or
  spurious "already exists — needs to be imported" for a resource that exists** —
  ARM read-after-write lag (GET after PUT briefly 404s), seen on
  vnet/nsg/nic. Recovery: `terraform import <address> <azure-id>`, then re-plan
  with `-refresh=false`. If `import` errors on an unrelated output, comment it
  out, import, restore.

## Testing

```bash
cd generated/<lab>/terraform/azure && terraform init -backend=false && terraform validate && terraform plan
```

`validate` needs no creds; `plan` needs `az login`/`ARM_*`. Without creds,
`validate` is the bar; `image_id` was verified to `validate` + a tfvars
inspection (resolves to the right ID for its machine group, `null` elsewhere).
Re-verify with a real `plan`/`apply` against a subscription that has the image.

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
  **The 2022/2025 server and both client (10/11) SKUs are best-effort** —
  GOAD's own file carries the same caveat: verify with
  `az vm image list --publisher <p> --offer <o> --all -o table` before a real
  deploy, since Azure marketplace SKU names/availability drift over time.
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
  `ad/GOAD/providers/azure/windows.tf`).
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

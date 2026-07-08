---
name: infra-proxmox
description: >
  Renders the on-prem Proxmox VE compute + network layer for a lab: Windows VMs
  cloned from operator-maintained templates (only cloudbase-init required —
  WinRM + the `ansible` admin are bootstrapped at first boot via cloudbase-init
  user-data), a WireGuard bastion with the only routable IP, and a
  deny-by-default Proxmox firewall — the on-prem sibling of infra-azure +
  network-topology. Consumes lab-manifest.json's network_plan and emits
  templates/terraform/proxmox/. Unlike Azure there is no marketplace and no VM
  extension, so images come from clones and WinRM is bootstrapped by an injected
  cloudbase-init user-data script (the on-prem twin of Azure's CustomScriptExtension).
---

# infra-proxmox

## When to use this skill

- During `/generate`, when the lab's `lab.provider` is `proxmox`.
  `scripts/forge.py`'s `render_proxmox_terraform()` copies
  `templates/terraform/proxmox/` verbatim into
  `generated/<lab>/terraform/proxmox/` and writes `terraform.tfvars.json`
  (spec-derived) + `secrets.auto.tfvars.json` (gitignored). It does NOT bake
  host specifics.

## How this differs from Azure (the four things Azure gives for free)

| Concern | Azure (infra-azure) | Proxmox (this skill) |
|---|---|---|
| Windows image | marketplace `publisher/offer/sku` | **clone a template** the operator maintains (`var.template_map` keyed by `machines[].os`) |
| WinRM bootstrap | `CustomScriptExtension` at boot | **cloudbase-init user-data** at first boot (`cloudinit/windows-bootstrap.ps1.tpl`, injected as a snippet) — no VM extensions on Proxmox, and no WinRM baked in the template |
| Static IP | azurerm sets it | **cloud-init / cloudbase-init** in the clone (template must have cloudbase-init — the ONE remaining template prerequisite) |
| Remote state | Azure Storage backend | **local backend** — documented relaxation of CLAUDE.md #4 |
| auto_shutdown | native DevTest schedule | **best-effort cron** on the deploy host (deploy.sh), hitting the Proxmox API |
| Cost | per-hour SKU | no billing; rates are $0, budget_alert_usd is informational |

## What it generates (`templates/terraform/proxmox/`)

One Terraform root module (bpg/proxmox provider):

| File | Content |
|---|---|
| `versions.tf` | provider pin (`bpg/proxmox ~> 0.66`), **local** backend, `PROXMOX_VE_*` env auth (never baked) |
| `main.tf` | a `proxmox_virtual_environment_pool` per lab (the on-prem analog of the Azure resource group) |
| `network.tf` | cluster firewall enable + per-VM deny-by-default (`input_policy DROP`) with narrow ACCEPT rules (mgmt subnet + own domain); bastion opens only WireGuard UDP |
| `windows.tf` | one `proxmox_virtual_environment_vm` per host, **cloned** from `var.template_map[os]`, private-only NIC on `lab_bridge` with a **per-domain VLAN tag**, static IP via cloud-init; a shared `proxmox_virtual_environment_file` snippet (`cloudinit/windows-bootstrap.ps1.tpl`) referenced as each VM's `initialization.user_data_file_id` bootstraps WinRM + the admin/`ansible` accounts at first boot |
| `bastion.tf` | Ubuntu clone with the only routable IP (static on `mgmt_bridge`), WireGuard cloud-init snippet uploaded via the API, SSH key written to `ssh_keys/bastion.pem` |
| `outputs.tf` | `bastion_public_ip` (named to match Azure so the shared deploy-time WireGuard step reads it identically), `windows_hosts`, `pool_id` |
| `host.auto.tfvars.example.json` | reference for the per-deployer host binding |

## Host independence (the account-independence convention)

The generated `terraform.tfvars.json` holds ONLY spec-derived, host-independent
values (identical on any Proxmox host). The host-specific inputs — `node_name`,
`datastore_id`, `mgmt_bridge`, `lab_bridge`, `template_map`,
`bastion_template_id`, `jumpbox_external_ip/prefix/gateway` — come from a
gitignored `host.auto.tfvars.json` the deployer fills from the committed
`host.auto.tfvars.example.json`. Plus the env: `PROXMOX_VE_ENDPOINT`,
`PROXMOX_VE_API_TOKEN`, and `PROXMOX_VE_INSECURE=true` for self-signed certs.
So the same generated lab deploys on anyone's cluster without editing the spec.

## Template prerequisites (operator-maintained)

The Windows templates referenced by `template_map` MUST have, baked in, exactly
ONE thing:

1. **cloudbase-init**, with its `UserDataPlugin` enabled (the default). It is
   needed to apply the static `ip_config` from Terraform AND to run the
   first-boot user-data that does everything else.

Everything else is bootstrapped at first boot and no longer needs baking:

- **WinRM** (HTTPS 5986 + Basic + self-signed cert, matching the Ansible
  inventory) and
- the **`ansible` local admin** (plus the `purpleforge` admin) accounts

are created by `cloudinit/windows-bootstrap.ps1.tpl`, uploaded once as a Proxmox
snippet (`proxmox_virtual_environment_file.windows_bootstrap`) and referenced by
every Windows VM's `initialization.user_data_file_id`. cloudbase-init runs it as
SYSTEM. The script is **idempotent and fully offline** (the lab bridge has no
internet uplink, so the WinRM setup is inlined, not downloaded like Azure's
ConfigureRemotingForAnsible.ps1) — so a legacy template that DOES have WinRM +
`ansible` pre-baked still deploys unchanged. Why cloudbase-init is an
unavoidable floor: a guest with zero in-guest agents (no cloudbase-init, no
qemu-guest-agent, no pre-enabled WinRM) exposes no channel for the hypervisor or
the network to configure it — that is a QEMU/Windows reality, not a PurpleForge
limitation.

The bastion template is an Ubuntu 22.04+ cloud-init image with
qemu-guest-agent. There is still no Packer/ISO automation for the Windows
templates — that was an explicit scope decision; the cloudbase-init user-data
bootstrap is what removed the need for it.

## Networking model (isolation invariant #1)

- Lab traffic rides `lab_bridge` with **one VLAN tag per domain** (assigned
  `100 + index` by `forge.py`, deterministic). Windows VMs are private-only —
  never a routable/bridged-to-LAN interface.
- The **Proxmox firewall** enforces deny-by-default: `input_policy DROP` on
  every lab VM, ACCEPT only from the management subnet (i.e. only via the
  WireGuard bastion) and the host's own domain subnet. This mirrors the Azure
  per-domain NSG.
- **Inter-VLAN L3 routing is deploy-time, not in Terraform** — like the Azure
  layer leaves WireGuard peer wiring to `deploy.sh`. Azure's VNet routes
  subnets for free; on Proxmox the bastion becomes that router:
  `deploy-proxmox.sh.j2`'s `route_lab` step brings up a VLAN sub-interface on
  the bastion's lab-side NIC for each domain, holding that domain's `.254`
  gateway IP (the address Windows hosts default-route to — see
  `windows.tf`/`variables.tf` `domains.*.gateway_ip`). This is why the gateway
  is the on-subnet `.254`, never the mgmt-subnet bastion IP (a gateway must be
  on-link).

## Known limitations / iteration notes

- auto_shutdown is best-effort (cron on the deploy host). A truly host-side
  schedule would need SSH to the PVE node (only the API token is assumed).
- The bastion VLAN sub-interfaces are set at deploy (idempotent) but not made
  persistent across a bastion reboot; re-running `deploy.sh` re-asserts them.
- Multi-domain trusts work (the bastion forwards between all lab VLANs), but
  were not yet exercised on a live multi-domain Proxmox deploy.

## Do NOT

- Bake `node_name`/bridges/datastore/template ids or the endpoint/token into
  the committed files — they are per-deployer (host.auto.tfvars.json + env).
- Add a `public_ip`-equivalent routable NIC to any Windows VM. Only the bastion
  is routable (invariant #1).
- Re-declare the cloned template's disk/os type in `windows.tf` — it is
  inherited; re-declaring risks mismatching the template's real ostype.

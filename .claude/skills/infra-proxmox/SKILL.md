---
name: infra-proxmox
description: >
  Renders the on-prem Proxmox VE compute + network layer: Windows VMs cloned from
  operator-maintained templates (only cloudbase-init required — WinRM + the
  `ansible` admin are bootstrapped at first boot via cloudbase-init user-data), a
  WireGuard bastion with the only routable IP, and a deny-by-default Proxmox
  firewall. The on-prem sibling of infra-azure + network-topology. Consumes
  network_plan, emits templates/terraform/proxmox/.
---

# infra-proxmox

## When to use

- `/generate`, when `lab.provider` is `proxmox`. `forge`'s
  `render_proxmox_terraform()` copies `templates/terraform/proxmox/` verbatim to
  `generated/<lab>/` + writes `terraform.tfvars.json` (spec-derived) +
  `secrets.auto.tfvars.json` (gitignored). It does NOT bake host specifics.

## vs Azure (the four things Azure gives for free)

| Concern | Azure | Proxmox |
|---|---|---|
| Windows image | marketplace sku | **clone a template** (`var.template_map` by `machines[].os`) |
| WinRM bootstrap | CustomScriptExtension | **cloudbase-init user-data** at first boot (`cloudinit/windows-bootstrap.ps1.tpl`) — no VM extensions on Proxmox |
| Static IP | azurerm | cloud-init/cloudbase-init in the clone |
| Remote state | Azure Storage | **local backend** — documented relaxation of invariant #4 |
| auto_shutdown | DevTest schedule | **best-effort cron** on the deploy host |
| Cost | per-hour SKU | none; rates $0, budget_alert_usd informational |

## What it generates (bpg/proxmox provider, one root module)

| File | Content |
|---|---|
| `versions.tf` | provider pin (`bpg/proxmox ~> 0.66`), **local** backend, `PROXMOX_VE_*` env auth |
| `main.tf` | one `proxmox_virtual_environment_pool` per lab (the RG analog) |
| `network.tf` | cluster firewall + per-VM deny-by-default (`input_policy DROP`), ACCEPT only mgmt subnet + own domain; bastion opens only WireGuard UDP |
| `windows.tf` | one VM per host, **cloned** from `template_map[os]`, private-only NIC on `lab_bridge` with a per-domain VLAN tag, static IP via cloud-init; a shared snippet (`windows-bootstrap.ps1.tpl`) as each VM's `initialization.user_data_file_id` bootstraps WinRM + admin/`ansible` at first boot |
| `bastion.tf` | Ubuntu clone, only routable IP (static on `mgmt_bridge`), WireGuard cloud-init snippet, SSH key to `ssh_keys/bastion.pem` |
| `outputs.tf` | `bastion_public_ip` (named to match Azure so deploy's WireGuard step reads it identically), `windows_hosts`, `pool_id` |
| `host.auto.tfvars.example.json` | reference for the per-deployer host binding |

## Host independence

`terraform.tfvars.json` holds ONLY spec-derived, host-independent values.
Host-specific inputs (`node_name`, `datastore_id`, `mgmt_bridge`, `lab_bridge`,
`template_map`, `bastion_template_id`, `jumpbox_external_ip/prefix/gateway`) come
from a gitignored `host.auto.tfvars.json` the deployer fills from the committed
example. Plus env: `PROXMOX_VE_ENDPOINT`, `PROXMOX_VE_API_TOKEN`,
`PROXMOX_VE_INSECURE=true` for self-signed certs. Same lab deploys on any cluster.

## Template prerequisites (operator-maintained)

Windows templates need exactly ONE thing baked in: **cloudbase-init** (with
`UserDataPlugin` enabled). It applies the static `ip_config` AND runs the
first-boot user-data. Everything else is bootstrapped at first boot:

- **WinRM** (HTTPS 5986 + Basic + self-signed) and the **`ansible`/`purpleforge`
  admin** accounts, created by `windows-bootstrap.ps1.tpl` (uploaded once as a
  snippet, referenced by every VM, run as SYSTEM). It's idempotent and fully
  offline (the lab bridge has no uplink, so WinRM setup is inlined), so a legacy
  template that DOES have WinRM pre-baked still deploys unchanged.

Why cloudbase-init is an unavoidable floor: a guest with zero in-guest agents
exposes no channel to configure it — a QEMU/Windows reality. The bastion template
is Ubuntu 22.04+ cloud-init with qemu-guest-agent. No Packer/ISO automation for
Windows templates (explicit scope decision — cloudbase-init removed the need).

## Networking (invariant #1)

- Lab traffic on `lab_bridge` with **one VLAN tag per domain** (`100 + index`,
  deterministic). Windows VMs private-only — never a routable NIC.
- **Proxmox firewall** deny-by-default: `input_policy DROP` on every lab VM,
  ACCEPT only from the mgmt subnet (i.e. the bastion) + own domain subnet.
- **Inter-VLAN L3 routing is deploy-time, not Terraform** — the bastion is the
  router: `deploy-proxmox.sh.j2`'s `route_lab` brings up a VLAN sub-interface on
  the bastion's lab NIC per domain, holding that domain's `.254` gateway (a
  gateway must be on-link — that's why it's the on-subnet `.254`, never the
  bastion's mgmt IP).

## Limitations

See [`PROXMOX-DEPLOY-RUNBOOK.md`](../../../PROXMOX-DEPLOY-RUNBOOK.md) (written
before this skill's output was exercised on a live PVE host — best-known, not
verified).

- auto_shutdown is best-effort cron (a host-side schedule would need SSH to the
  node; only the API token is assumed).
- Bastion VLAN sub-interfaces are set at deploy (idempotent) but not persistent
  across a bastion reboot; re-running `deploy.sh` re-asserts them.
- Multi-domain trusts work (bastion forwards between VLANs) but weren't yet run on
  a live multi-domain Proxmox deploy.

## Do NOT

- Bake `node_name`/bridges/datastore/template ids or the endpoint/token into
  committed files (per-deployer).
- Add a routable NIC to any Windows VM — only the bastion is routable (#1).
- Re-declare the cloned template's disk/os type in `windows.tf` — it's inherited;
  re-declaring risks mismatching the real ostype.

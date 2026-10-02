---
name: network-topology
description: >
  Generates the VNet/VPC, subnets, WireGuard bastion, and deny-by-default NSG/SG
  rules for a lab, enforcing CLAUDE.md invariant #1 (no vulnerable host ever gets
  a public IP or inbound RDP/WinRM from the internet; all access goes through the
  WireGuard bastion). Consumes lab-manifest.json's network_plan; feeds
  infra-aws/infra-azure, which attach compute to these subnets.
---

# network-topology

## When to use

- During `/generate`, right after `lab-spec` produced `lab-manifest.json`, before
  `infra-azure` renders compute.
- Whenever changing the isolation model (subnets, bastion, NSG/SG rules).

## Why it exists (don't skip)

`vendor/GOAD`'s network layer does NOT meet the isolation bar and must not be
reused: its Azure `network.tf` has **no NSG**; its `jumpbox.tf` gives the jumpbox
a public IP with SSH and no security group; its AWS `whitelist_cidr` defaults to
`0.0.0.0/0`. GOAD assumes a disposable single-operator lab; PurpleForge requires
deny-by-default NSG/SG + VPN-only (invariant #1), so this skill replaces GOAD's
network layer entirely.

## What it generates (Azure — `templates/terraform/azure/{network,bastion}.tf`)

- **One VNet** = `network_plan.supernet` (`/16`, deterministic from `lab.name`,
  see `forge.stable_octet`).
- **One management subnet** (`/24`) with only the WireGuard bastion. Its NSG:
  one `deny-all-inbound` baseline + narrow allows from `bastion.tf` — WireGuard
  UDP from `wireguard_allowed_cidrs` (defaults to internet: that's the VPN's job)
  and opt-in SSH from `bastion_ssh_allowed_cidrs` (empty by default → no rule).
- **One subnet per domain** (`network_plan.domains.<domain>.subnet`), each NSG:
  allow ALL from the management subnet, allow intra-subnet (AD auth/replication),
  deny inbound from `Internet`, `deny-all-inbound` baseline. No Windows NIC ever
  gets a public IP. The management-subnet rule is deliberately NOT narrowed to
  WinRM: the subnet is only reachable via the bastion anyway, so narrowing the
  dest port only blocks legit operator traffic (SMB/RDP). Invariant #1 is
  enforced by `source_address_prefix` = management subnet, not by dest port.
- **The WireGuard bastion** — Ubuntu VM, the ONLY host with a public IP. Server
  keypair generated locally on first boot (`wg genkey`/`wg pubkey` in
  `cloudinit/wireguard-bastion.yaml.tpl`), NOT by Terraform — WireGuard keys are
  raw Curve25519, so `tls_private_key` can't generate them (don't reintroduce
  that). IP forwarding + NAT MASQUERADE let peers reach the private subnets.

## Adding a WireGuard peer (not automated)

Server side only is provisioned. To connect an operator:

```bash
# on the bastion (ssh key: generated/<lab>/terraform/azure/ssh_keys/bastion.pem):
wg genkey | tee client.key | wg pubkey > client.pub
sudo wg set wg0 peer $(cat client.pub) allowed-ips 10.250.250.2/32
```

## Testing (structural — no live apply)

```bash
cd generated/<lab>/terraform/azure && terraform init -backend=false && terraform validate && terraform plan
```

A clean plan shows: zero public IPs on any Windows NIC, exactly one public IP
(the bastion), every domain NSG's only internet-facing rule an explicit `Deny`.

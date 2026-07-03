---
name: network-topology
description: >
  Generates the VNet/VPC, subnets, WireGuard bastion, and deny-by-default
  NSG/SG rules for a lab, enforcing CLAUDE.md invariant #1 (no vulnerable host
  ever gets a public IP or inbound RDP/WinRM from the internet; all access
  goes through the WireGuard bastion). Consumes lab-manifest.json's
  network_plan (produced by the lab-spec skill); feeds infra-aws/infra-azure,
  which attach compute to the subnets this skill defines.
---

# network-topology

## When to use this skill

- During `/generate`, right after `lab-spec` has produced
  `generated/<lab>/lab-manifest.json`, and before `infra-aws`/`infra-azure`
  render compute.
- Whenever asked to reason about or change the lab's network isolation model
  (subnets, bastion, NSG/SG rules).

## Why this skill exists (don't skip it)

`vendor/GOAD`'s own Azure/AWS Terraform is a fine reference for VM shapes, but
its network layer does **not** meet PurpleForge's isolation bar and must not
be reused as-is:

- `vendor/GOAD/template/provider/azure/network.tf` defines a VNet/subnet and
  NICs but **no NSG at all** — nothing stops inbound traffic from the
  internet to anything in that subnet.
- `vendor/GOAD/template/provider/azure/jumpbox.tf` gives the Ubuntu jumpbox a
  public IP with SSH and no security group in front of it.
- `vendor/GOAD/template/provider/aws/variables.tf`'s `whitelist_cidr`
  defaults to `["0.0.0.0/0"]` — the AWS jumpbox is reachable from anywhere.

GOAD can get away with this because it assumes a disposable, short-lived,
single-operator lab. PurpleForge cannot: CLAUDE.md invariant #1 requires
deny-by-default NSG/SG and VPN-only access, so this skill replaces GOAD's
network layer entirely rather than patching it.

## What it generates (Azure — `templates/terraform/azure/{network,bastion}.tf`)

- **One VNet** sized to `network_plan.supernet` (a `/16`, deterministic from
  `lab.name` — see `scripts/forge.py:stable_octet`).
- **One management subnet** (`network_plan.management_subnet`, a `/24`)
  containing only the WireGuard bastion. Its NSG has a single explicit
  `deny-all-inbound` baseline rule, plus narrowly-scoped allow rules added by
  `bastion.tf`: WireGuard UDP from `wireguard_allowed_cidrs` (defaults to the
  internet — that's the VPN's job, not a Windows-service exposure) and,
  opt-in only, direct SSH from `bastion_ssh_allowed_cidrs` (empty by
  default — no rule is created at all unless explicitly set).
- **One subnet per forest domain** (`network_plan.domains.<domain>.subnet`),
  each with an NSG that allows WinRM (5985/5986) *only* from the management
  subnet, allows intra-subnet traffic (AD auth/replication), explicitly
  denies inbound from `Internet`, and ends with a `deny-all-inbound`
  baseline. No Windows host NIC in these subnets ever gets a
  `azurerm_public_ip`/`aws_eip` attached — see `templates/terraform/azure/windows.tf`.
- **The WireGuard bastion** — an Ubuntu VM, the *only* host with a public IP
  in the whole lab. The server keypair is generated locally on first boot
  (`wg genkey`/`wg pubkey` inside
  `templates/terraform/azure/cloudinit/wireguard-bastion.yaml.tpl`), not by
  Terraform — WireGuard keys are raw Curve25519 values, not PEM/OpenSSH keys,
  so `tls_private_key` cannot generate them (this was caught and fixed during
  Phase 2; don't reintroduce it). IP forwarding + NAT
  (`iptables -t nat ... MASQUERADE`) let tunnel clients reach the lab's
  private subnets once a peer is added.

## Operational note: adding a WireGuard peer (not automated yet)

This skill provisions the bastion server side only. To let a specific
operator connect:

```bash
# on the bastion (via its SSH key, generated/<lab>/terraform/azure/ssh_keys/bastion.pem):
wg genkey | tee client.key | wg pubkey > client.pub   # or generate client-side and only send the pubkey
sudo wg set wg0 peer $(cat client.pub) allowed-ips 10.250.250.2/32
```

Automating peer distribution (e.g. an Ansible role or a `scripts/wg-add-peer.sh`
helper) is left for a later phase — track it if the project needs multi-operator
labs; a single-operator lab only needs the one manual step above.

## Testing this skill

There is no live-apply test in CI (that needs real cloud credentials).
Validate structurally instead:

```bash
cd generated/<lab>/terraform/azure && terraform init -backend=false && terraform validate && terraform plan
```

A clean plan must show: zero `azurerm_public_ip`/`aws_eip` resources attached
to a Windows VM's NIC, exactly one public IP (the bastion), and every domain
NSG's only internet-facing rule being an explicit `Deny`.

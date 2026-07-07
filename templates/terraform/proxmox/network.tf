# Network isolation (CLAUDE.md invariant #1) on Proxmox is enforced by the
# built-in firewall, the on-prem analog of the Azure NSGs. Layer 2 isolation
# comes from VLAN tags per domain on the lab bridge (see windows.tf's
# network_device); layer 3 deny-by-default comes from a DROP input policy on
# every lab VM, with narrow ACCEPT rules that mirror the Azure per-domain NSG:
# a Windows host accepts inbound only from the management subnet (i.e. only via
# the WireGuard bastion) and from its own domain subnet (AD replication/auth).
#
# ROUTING NOTE: like the Azure layer leaves the WireGuard peer wiring to
# deploy-time (deploy.sh wg_up), inter-VLAN L3 routing between the management
# subnet and the domain VLANs (and between domain VLANs for multi-domain
# trusts) is completed in the deploy-time bastion configuration, not here. This
# module provisions the topology + firewall; the bastion becomes the router for
# the lab VLANs in the proxmox deploy branch (iteration 2). Windows hosts point
# their default gateway at the bastion's internal IP accordingly (windows.tf).

# Per-VM firewall rules only take effect if the cluster firewall is enabled.
# This is a cluster-wide toggle, but the policies stay ACCEPT so VMs that don't
# opt into their own DROP policy (everything outside this lab) are unaffected —
# isolation here is imposed per-VM below, never cluster-wide.
resource "proxmox_virtual_environment_cluster_firewall" "this" {
  enabled       = true
  input_policy  = "ACCEPT"
  output_policy = "ACCEPT"
}

# --- Windows hosts: deny-by-default, reachable only from management + own domain ---
resource "proxmox_virtual_environment_firewall_options" "windows" {
  for_each = local.machines_by_name

  node_name     = var.node_name
  vm_id         = proxmox_virtual_environment_vm.windows[each.key].vm_id
  enabled       = true
  input_policy  = "DROP"
  output_policy = "ACCEPT"

  depends_on = [proxmox_virtual_environment_cluster_firewall.this]
}

resource "proxmox_virtual_environment_firewall_rules" "windows" {
  for_each = local.machines_by_name

  node_name = var.node_name
  vm_id     = proxmox_virtual_environment_vm.windows[each.key].vm_id

  rule {
    type    = "in"
    action  = "ACCEPT"
    source  = var.management_cidr
    comment = "allow from management subnet (WireGuard bastion / operator tunnel)"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    source  = var.domains[each.value.domain].subnet_cidr
    comment = "allow intra-domain (AD replication/auth)"
  }

  depends_on = [proxmox_virtual_environment_firewall_options.windows]
}

# --- Bastion: the only host exposing an inbound port, and only WireGuard UDP ---
resource "proxmox_virtual_environment_firewall_options" "bastion" {
  node_name     = var.node_name
  vm_id         = proxmox_virtual_environment_vm.bastion.vm_id
  enabled       = true
  input_policy  = "DROP"
  output_policy = "ACCEPT"

  depends_on = [proxmox_virtual_environment_cluster_firewall.this]
}

resource "proxmox_virtual_environment_firewall_rules" "bastion" {
  node_name = var.node_name
  vm_id     = proxmox_virtual_environment_vm.bastion.vm_id

  dynamic "rule" {
    for_each = toset(var.wireguard_allowed_cidrs)
    content {
      type    = "in"
      action  = "ACCEPT"
      source  = rule.value
      proto   = "udp"
      dport   = tostring(var.wireguard_port)
      comment = "allow WireGuard"
    }
  }

  depends_on = [proxmox_virtual_environment_firewall_options.bastion]
}

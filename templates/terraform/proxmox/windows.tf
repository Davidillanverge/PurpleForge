# Windows VMs are CLONED from templates the operator maintains (var.template_map
# keyed by machines[].os), NOT installed from ISO and NOT pulled from a
# marketplace — Proxmox has neither. The template is expected to already have
# WinRM enabled and the local `ansible` admin account baked in (the Azure layer
# does this at boot with a CustomScriptExtension; Proxmox has no VM extensions,
# so it moves into the golden template). Static IPs are injected via cloud-init,
# which on Windows requires cloudbase-init to be installed in the template.
#
# Every NIC is private-only on the isolated lab bridge with a per-domain VLAN
# tag: no Windows host ever gets a routable/bridged-to-LAN interface. WinRM is
# reachable only from the management subnet through the firewall (network.tf),
# i.e. only via the WireGuard bastion — CLAUDE.md invariant #1.

locals {
  # Per-role cores/memory(MiB) defaults, overridable wholesale by
  # var.vm_specs_overrides. Modest sizing suitable for a lab node; bump via the
  # override for a busy DC.
  spec_map = merge({
    "domain-controller" = { cores = 2, memory = 4096 }
    "member-server"     = { cores = 2, memory = 4096 }
    "workstation"       = { cores = 2, memory = 2048 }
  }, var.vm_specs_overrides)

  machines_by_name = { for m in var.machines : m.name => m }
}

resource "proxmox_virtual_environment_vm" "windows" {
  for_each = local.machines_by_name

  name      = each.value.name
  node_name = var.node_name
  pool_id   = proxmox_virtual_environment_pool.lab.id
  # Boot the VM after clone so first-boot cloudbase-init applies the static IP
  # and WinRM comes up ahead of the Ansible phase.
  started = true

  clone {
    # Per-host override wins; otherwise the os->template map. full=true makes an
    # independent copy so destroying the lab never touches the source template.
    vm_id = coalesce(each.value.template_id, var.template_map[each.value.os])
    full  = true
  }

  agent {
    enabled = true
  }

  cpu {
    cores = local.spec_map[each.value.role].cores
    type  = "x86-64-v2-AES"
  }

  memory {
    dedicated = local.spec_map[each.value.role].memory
  }

  network_device {
    bridge  = var.lab_bridge
    vlan_id = var.domains[each.value.domain].vlan_id
  }

  initialization {
    datastore_id = var.datastore_id

    ip_config {
      ipv4 {
        address = "${each.value.ip}/${split("/", var.domains[each.value.domain].subnet_cidr)[1]}"
        # Default gateway = the bastion's ON-SUBNET address for this domain (the
        # .254 that deploy.sh brings up as the bastion's VLAN sub-interface — a
        # gateway must be on-link, so it can't be the mgmt-subnet IP). The
        # bastion routes the lab VLANs at deploy time (network.tf ROUTING NOTE);
        # an unreachable gateway at first boot is harmless to Windows.
        gateway = var.domains[each.value.domain].gateway_ip
      }
    }

    user_account {
      username = var.admin_username
      password = var.admin_password
    }
  }

  # `operating_system.type`, disks and BIOS are inherited from the cloned
  # template, so they are not re-declared here (re-declaring os type risks
  # mismatching the template's real ostype). `os` in the spec still drives the
  # downstream ansible-lockdown/OS behavior, independent of the template.

  lifecycle {
    # Proxmox reports a handful of clone-inherited fields (disk layout, cpu
    # flags) as diffs on refresh; don't fight the template on re-apply.
    ignore_changes = [disk, clone]
  }
}

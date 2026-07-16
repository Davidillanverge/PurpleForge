# Windows VMs are CLONED from templates the operator maintains (var.template_map
# keyed by machines[].os), NOT installed from ISO and NOT pulled from a
# marketplace — Proxmox has neither. The ONLY thing the template must have baked
# in is cloudbase-init (needed to apply the static IP, and to run the first-boot
# user-data below). WinRM and the local `ansible` admin are NOT required in the
# template: they are bootstrapped at first boot by cloudinit/windows-bootstrap.ps1.tpl,
# injected as cloudbase-init user-data (the on-prem twin of the Azure layer's
# ConfigureRemotingForAnsible.ps1 CustomScriptExtension). The script is
# idempotent, so a template that DOES have them baked still works.
#
# Every NIC is private-only on the isolated lab bridge with a per-domain VLAN
# tag: no Windows host ever gets a routable/bridged-to-LAN interface. WinRM is
# reachable only from the management subnet through the firewall (network.tf),
# i.e. only via the WireGuard bastion — CLAUDE.md invariant #1.

# First-boot bootstrap user-data, uploaded once as a Proxmox snippet and
# referenced by every Windows VM's initialization.user_data_file_id below (same
# mechanism the bastion uses for its cloud-init). cloudbase-init's UserDataPlugin
# runs it as SYSTEM on first boot to create the admin + `ansible` accounts and
# stand up the WinRM HTTPS/5986 + Basic listener the Ansible inventory expects.
# It is shared by all hosts (same accounts + WinRM config everywhere); the
# per-host static IP and hostname come from initialization/metadata, not here.
resource "proxmox_virtual_environment_file" "windows_bootstrap" {
  content_type = "snippets"
  datastore_id = var.snippets_datastore_id
  node_name    = var.node_name

  source_raw {
    # .yaml to match the bastion snippet Proxmox already accepts as user-data;
    # the content is a cloudbase-init `#ps1_sysnative` PowerShell script (the
    # leading header, not the extension, is what tells cloudbase-init to run it).
    file_name = "${var.lab_name}-windows-bootstrap.yaml"
    data = templatefile("${path.module}/cloudinit/windows-bootstrap.ps1.tpl", {
      admin_username   = var.admin_username
      admin_password   = var.admin_password
      ansible_password = var.ansible_password
      supernet         = var.supernet
    })
  }
}

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
    # Template resolution, most specific first: a per-host machines[].template_id
    # pin > the deploy-time per-role template_id_overrides (deploy.sh, from
    # PF_TEMPLATE_ID) > the os->template map (var.template_map, host.auto.tfvars).
    # lookup(...,null) instead of a bare index so an overridden host needs no
    # template_map entry for its os; coalesce still errors clearly if nothing
    # resolves. var.full_clone (default false) = linked clone: instant + tiny on
    # lvmthin, vs a full 60GB copy per VM that crawls on a single-disk host. The
    # template disk stays present (it's a template), so destroying the lab never
    # touches it either way.
    vm_id = coalesce(
      each.value.template_id,
      lookup(var.template_id_overrides, each.value.role, null),
      lookup(var.template_map, each.value.os, null),
    )
    full = var.full_clone
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

    # First-boot bootstrap (WinRM + the admin/ansible accounts) — see the
    # windows_bootstrap snippet above. This removes the need for a
    # WinRM-and-ansible-baked golden template; cloudbase-init is the only
    # template prerequisite left.
    user_data_file_id = proxmox_virtual_environment_file.windows_bootstrap.id

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

    # Upstream DNS for the FIRST-boot window only. GOAD's `common` role installs
    # PowerShellGet/NuGet from the internet BEFORE the DC is promoted, so the box
    # needs a resolver it can actually reach (the isolated lab had no DNS -> an
    # inherited/unreachable server -> name resolution failed). The lab reaches the
    # internet via the bastion NAT (deploy.sh route_lab). GOAD repoints DNS to the
    # domain controller during promotion/join, so this only matters at first boot.
    dns {
      servers = var.lab_upstream_dns
    }

    # Keep user_account so cloudbase-init also sets the admin password the normal
    # way where the provider still honours cipassword alongside a custom
    # user_data; the bootstrap script re-asserts it regardless, so the two never
    # disagree. The `ansible` account is created only by the script.
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

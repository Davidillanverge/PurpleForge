# WireGuard bastion — the ONLY host with a routable IP (a static address on the
# mgmt bridge, replacing Azure's public IP). It exposes a single UDP port
# (WireGuard, via the firewall in network.tf); no RDP/WinRM ever reaches a
# Windows host except through this tunnel, matching CLAUDE.md invariant #1.
# Cloned from an Ubuntu cloud-init template (var.bastion_template_id); the
# WireGuard server + login user + SSH key are set up by the cloud-init snippet
# uploaded below.

resource "tls_private_key" "bastion_ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# NOTE: WireGuard keys are raw Curve25519 values (`wg genkey`/`wg pubkey`),
# NOT PEM/OpenSSH keys — tls_private_key cannot generate them. The server
# keypair is generated on first boot by the cloud-init snippet, so the private
# key never transits Terraform state. tls_private_key here is only the SSH key
# used to reach the bastion for the post-deploy WireGuard peer wiring.

# Upload the WireGuard cloud-init user-data as a Proxmox snippet, then reference
# it from the bastion's initialization. The snippets datastore must have the
# `snippets` content type enabled.
resource "proxmox_virtual_environment_file" "bastion_cloudinit" {
  content_type = "snippets"
  datastore_id = var.snippets_datastore_id
  node_name    = var.node_name

  source_raw {
    file_name = "${var.lab_name}-wg-bastion.yaml"
    data = templatefile("${path.module}/cloudinit/wireguard-bastion.yaml.tpl", {
      jumpbox_username   = var.jumpbox_username
      ssh_authorized_key = trimspace(tls_private_key.bastion_ssh.public_key_openssh)
      wireguard_port     = var.wireguard_port
      # Fixed tunnel subnet, deliberately outside any lab supernet (matches the
      # Azure layer) so it never collides with a lab's addressing.
      tunnel_cidr = "10.250.250.1/24"
      vnet_cidr   = var.supernet
    })
  }
}

resource "proxmox_virtual_environment_vm" "bastion" {
  name      = "${var.lab_name}-bastion"
  node_name = var.node_name
  pool_id   = proxmox_virtual_environment_pool.lab.id
  started   = true

  clone {
    vm_id = var.bastion_template_id
    full  = var.full_clone
  }

  agent {
    enabled = true
  }

  cpu {
    cores = var.bastion_cores
    type  = "x86-64-v2-AES"
  }

  memory {
    dedicated = var.bastion_memory
  }

  # net0: routable NIC on the mgmt bridge (how the operator reaches WireGuard).
  network_device {
    bridge = var.mgmt_bridge
  }

  # net1: internal NIC on the isolated lab bridge — the tunnel's ingress into
  # the lab and (at deploy time) the router interface for the lab VLANs.
  network_device {
    bridge = var.lab_bridge
  }

  initialization {
    datastore_id      = var.datastore_id
    user_data_file_id = proxmox_virtual_environment_file.bastion_cloudinit.id

    # ip_config order maps to network_device order (net0 external, net1 internal).
    ip_config {
      ipv4 {
        address = "${var.jumpbox_external_ip}/${var.jumpbox_external_prefix}"
        gateway = var.jumpbox_external_gateway
      }
    }

    ip_config {
      ipv4 {
        address = "${var.jumpbox_private_ip}/${split("/", var.management_cidr)[1]}"
      }
    }
  }

  # Write the SSH private key next to this module (generated/<lab>/terraform/
  # proxmox/ssh_keys/), the same place and depth the Azure layer uses, so the
  # deploy-time WireGuard step finds it identically on both providers.
  provisioner "local-exec" {
    command = "mkdir -p ${path.module}/ssh_keys && printf '%s' '${tls_private_key.bastion_ssh.private_key_pem}' > ${path.module}/ssh_keys/bastion.pem && chmod 600 ${path.module}/ssh_keys/bastion.pem"
  }
}

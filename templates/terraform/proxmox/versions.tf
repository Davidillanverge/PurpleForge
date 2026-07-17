# PurpleForge — thin Proxmox VE Terraform layer (sibling of terraform/azure/).
# Mirrors the Azure layer's shape (one WireGuard bastion with the only routable
# IP, private-only Windows VMs, deny-by-default firewall) but targets an on-prem
# Proxmox VE cluster via the well-maintained bpg/proxmox provider. Windows VMs
# are CLONED from templates the operator maintains (WinRM + the `ansible` user
# baked in) — Proxmox has no marketplace and no VM extensions, so unlike the
# Azure layer there is no CustomScriptExtension WinRM bootstrap here (see
# windows.tf). Values come from terraform.tfvars.json (spec-derived, shareable)
# plus a gitignored host.auto.tfvars.json (this Proxmox host's node/bridges/
# datastore/template ids — see host.auto.tfvars.example.json). These .tf files
# stay plain HCL so `terraform validate`/`plan` catch real mistakes.
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.66"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # CLAUDE.md invariant #4 asks for remote state with locking. On an on-prem
  # Proxmox cluster there is no cloud object store to mint per-deployer (the
  # Azure layer uses an Azure Storage account); per the project decision this
  # layer deliberately relaxes #4 to a LOCAL backend with Terraform's local
  # state lock. State lives next to this module in generated/<lab>/terraform/
  # proxmox/terraform.tfstate — single-operator on-prem use. Point this at a
  # `pg`/`s3`(MinIO)/`http` backend instead if a shared state store exists.
  backend "local" {}
}

# Endpoint + API token are read from the environment, never baked into the
# generated files (same account-independence rule the Azure layer follows for
# the subscription): export before `terraform`/deploy —
#   PROXMOX_VE_ENDPOINT="https://pve.example.lan:8006/"
#   PROXMOX_VE_API_TOKEN="user@pam!tokenid=xxxxxxxx-xxxx-..."
#   PROXMOX_VE_INSECURE=true   # only if the PVE cert is self-signed
# SSH TO THE NODE IS REQUIRED. The bastion cloud-init user-data is uploaded as a
# `snippets` file (bastion.tf), and bpg can only upload snippets over SSH/SFTP —
# NOT the API (the API upload path covers `iso`/`vztmpl` only). So the deploy host
# must reach the PVE node over SSH with key auth, on ANY host (bare-metal LAN too,
# not just cloud): export
#   PROXMOX_VE_SSH_USERNAME=root
#   PROXMOX_VE_SSH_PRIVATE_KEY=... (or have the key loaded in your ssh-agent)
# and add the deploy host's pubkey to the node's /root/.ssh/authorized_keys.
# CLOUD-hosted Proxmox: the node reports its INTERNAL ip (unreachable from a remote
# deploy host), so also pin the reachable address with an ssh{node{}} block below.
# See PROXMOX-DEPLOY-RUNBOOK.md §0.
provider "proxmox" {
  # Connection settings come from PROXMOX_VE_* env vars. For a cloud-hosted node
  # reached over the internet, uncomment and set the reachable address so bpg's
  # snippet SSH targets the public IP instead of the node's self-reported internal IP:
  # ssh {
  #   node {
  #     name    = "<node_name>"
  #     address = "<proxmox-public-ip>"
  #   }
  # }
}

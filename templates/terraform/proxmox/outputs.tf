output "pool_id" {
  description = "Proxmox resource pool holding every VM in this lab (teardown/verify with `pvesh get /pools/<id>`)."
  value       = proxmox_virtual_environment_pool.lab.id
}

output "bastion_public_ip" {
  description = "Routable IP of the bastion on the mgmt bridge — connect WireGuard clients to this IP:port. Named bastion_public_ip (not _external) to match the Azure layer's output so the shared deploy-time WireGuard step reads it identically on both providers. The server's own WireGuard public key is generated on first boot (not in Terraform) — retrieve it post-deploy over SSH: `cat /etc/wireguard/publickey`."
  value       = var.jumpbox_external_ip
}

output "bastion_ssh_private_key_path" {
  value = "${path.module}/ssh_keys/bastion.pem"
}

output "windows_hosts" {
  description = "name -> private IP for every Windows VM (all private-only on the isolated lab bridge, reachable only via the WireGuard tunnel)."
  value       = { for m in var.machines : m.name => m.ip }
}

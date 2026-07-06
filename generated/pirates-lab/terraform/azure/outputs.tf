output "resource_group_name" {
  value = azurerm_resource_group.rg.name
}

output "bastion_public_ip" {
  description = "Connect WireGuard clients to this IP:port. The server's own WireGuard public key is generated on first boot (not known to Terraform) — retrieve it post-deploy, e.g. via `az vm run-command invoke ... --command-id RunShellScript --scripts 'cat /etc/wireguard/publickey'`."
  value       = azurerm_public_ip.bastion.ip_address
}

output "bastion_ssh_private_key_path" {
  value = "${path.module}/ssh_keys/bastion.pem"
}

output "windows_hosts" {
  description = "name -> private IP for every generated Windows VM (all private-IP-only, reachable only via the WireGuard tunnel)."
  value       = { for m in var.machines : m.name => azurerm_network_interface.windows[m.name].private_ip_address }
}

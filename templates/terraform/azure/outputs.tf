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

output "lab_endpoints" {
  description = "node -> {role, ip, probes} for EVERY node (bastion + Windows hosts). The generated deploy/start/reset scripts read this (terraform output -json) and open all probes' TCP sockets in parallel — no port or provider is hardcoded in the scripts."
  value = merge(
    { bastion = { role = "bastion", ip = azurerm_public_ip.bastion.ip_address, probes = lookup(var.endpoint_probes, "bastion", []) } },
    { for m in var.machines : m.name => { role = m.role, ip = azurerm_network_interface.windows[m.name].private_ip_address, probes = lookup(var.endpoint_probes, m.role, []) } },
  )
}

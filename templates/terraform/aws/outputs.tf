output "bastion_public_ip" {
  description = "Connect WireGuard clients to this IP:port. The server's own WireGuard public key is generated on first boot (not known to Terraform) — retrieve it post-deploy over SSH, e.g. `ssh -i ssh_keys/bastion.pem purpleforge@<ip> sudo cat /etc/wireguard/publickey`."
  value       = aws_eip.bastion.public_ip
}

output "bastion_ssh_private_key_path" {
  value = "${path.module}/ssh_keys/bastion.pem"
}

output "windows_hosts" {
  description = "name -> private IP for every generated Windows VM (all private-IP-only, reachable only via the WireGuard tunnel)."
  value       = { for m in var.machines : m.name => aws_network_interface.windows[m.name].private_ip }
}

output "region" {
  value = var.region
}

output "lab_endpoints" {
  description = "node -> {role, ip, probes} for EVERY node (bastion + Windows hosts). The generated deploy/start/reset scripts read this (terraform output -json) and open all probes' TCP sockets in parallel — no port or provider is hardcoded in the scripts."
  value = merge(
    { bastion = { role = "bastion", ip = aws_eip.bastion.public_ip, probes = lookup(var.endpoint_probes, "bastion", []) } },
    { for m in var.machines : m.name => { role = m.role, ip = aws_network_interface.windows[m.name].private_ip, probes = lookup(var.endpoint_probes, m.role, []) } },
  )
}

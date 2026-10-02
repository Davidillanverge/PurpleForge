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

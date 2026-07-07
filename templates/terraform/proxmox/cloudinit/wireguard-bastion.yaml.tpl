#cloud-config
# WireGuard server bootstrap for the PurpleForge bastion on Proxmox.
# Same server-side logic as the Azure layer's cloudinit (keys generated locally
# on first boot so the private key never transits Terraform state) but this
# variant is delivered as a full user-data snippet (uploaded via the Proxmox
# API, see bastion.tf), so it also creates the login user + injects the SSH key
# here — the Azure layer gets those from the azurerm VM's own admin_ssh_key.
package_update: true
packages:
  - wireguard-tools

users:
  - name: ${jumpbox_username}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ${ssh_authorized_key}

runcmd:
  - |
    umask 077
    wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
    PRIVKEY=$(cat /etc/wireguard/privatekey)
    cat > /etc/wireguard/wg0.conf <<WGCONF
    [Interface]
    Address = ${tunnel_cidr}
    ListenPort = ${wireguard_port}
    PrivateKey = $PRIVKEY
    PostUp = iptables -t nat -A POSTROUTING -s ${tunnel_cidr} -d ${vnet_cidr} -j MASQUERADE
    PostDown = iptables -t nat -D POSTROUTING -s ${tunnel_cidr} -d ${vnet_cidr} -j MASQUERADE
    # Peers are added post-deploy:
    #   wg set wg0 peer <client-pubkey> allowed-ips <client-tunnel-ip>/32
    WGCONF
    chmod 600 /etc/wireguard/wg0.conf
  - sysctl -w net.ipv4.ip_forward=1
  - sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  - systemctl enable wg-quick@wg0
  - systemctl start wg-quick@wg0

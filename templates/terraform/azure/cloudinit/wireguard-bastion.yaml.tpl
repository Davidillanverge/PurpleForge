#cloud-config
# WireGuard server bootstrap for the PurpleForge bastion.
# The server keypair is generated locally on first boot (wg genkey/wg pubkey)
# so the private key never transits Terraform state or plan output. Adding
# lab-user peers is a post-deploy operational step (see
# .claude/skills/network-topology/SKILL.md) — this script only brings up the
# server side with zero peers configured.
package_update: true
packages:
  - wireguard-tools

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

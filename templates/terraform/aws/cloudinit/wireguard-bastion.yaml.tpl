#cloud-config
# WireGuard server bootstrap for the PurpleForge bastion (AWS).
# The server keypair is generated locally on first boot (wg genkey/wg pubkey) so
# the private key never transits Terraform state or plan output. Adding lab-user
# peers is a post-deploy operational step — this script only brings up the
# server side with zero peers configured.
#
# This bastion ALSO acts as the NAT instance for the private domain subnets:
# their route tables default-route to this host's ENI (see network.tf), so in
# addition to the tunnel->VPC MASQUERADE it masquerades the whole VPC supernet
# out to the internet gateway. That is what gives the private, public-IP-less
# Windows hosts their egress (e.g. the user_data ConfigureRemotingForAnsible
# download) without a paid NAT Gateway.
package_update: true
packages:
  - wireguard-tools

runcmd:
  - |
    umask 077
    wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
    PRIVKEY=$(cat /etc/wireguard/privatekey)
    WANIF=$(ip route show default | awk '{print $5; exit}')
    cat > /etc/wireguard/wg0.conf <<WGCONF
    [Interface]
    Address = ${tunnel_cidr}
    ListenPort = ${wireguard_port}
    PrivateKey = $PRIVKEY
    # Tunnel clients reach the VPC:
    PostUp = iptables -t nat -A POSTROUTING -s ${tunnel_cidr} -d ${vpc_cidr} -j MASQUERADE
    PostDown = iptables -t nat -D POSTROUTING -s ${tunnel_cidr} -d ${vpc_cidr} -j MASQUERADE
    # NAT the private domain subnets' egress out to the internet gateway:
    PostUp = iptables -t nat -A POSTROUTING -s ${vpc_cidr} -o $WANIF -j MASQUERADE
    PostDown = iptables -t nat -D POSTROUTING -s ${vpc_cidr} -o $WANIF -j MASQUERADE
    # Peers are added post-deploy:
    #   wg set wg0 peer <client-pubkey> allowed-ips <client-tunnel-ip>/32
    WGCONF
    chmod 600 /etc/wireguard/wg0.conf
  - sysctl -w net.ipv4.ip_forward=1
  - sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  - systemctl enable wg-quick@wg0
  - systemctl start wg-quick@wg0

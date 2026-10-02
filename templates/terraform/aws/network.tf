# Network isolation (CLAUDE.md invariant #1): one VPC, a management subnet that
# only the WireGuard bastion lives in (the single subnet with a route to the
# internet gateway), and one private subnet per AD domain whose only inbound
# path is from the management subnet — i.e. only through the WireGuard tunnel.
#
# AWS security groups are stateful and default-deny for any inbound traffic not
# explicitly allowed, so "deny-by-default" is the platform behaviour here rather
# than an explicit deny rule you add (the opposite of an Azure NSG, which needs
# an explicit deny-all because subnets in a VNet allow each other by default).
# The isolation guarantee therefore lives in WHAT each SG allows: the bastion SG
# admits only the WireGuard UDP port from the internet, and the domain SG admits
# traffic only from the bastion SG and from peers in the same domain — never
# from the internet, and no Windows host ever gets a public IP.

resource "aws_vpc" "vpc" {
  cidr_block           = var.supernet
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.lab_name}-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags   = { Name = "${var.lab_name}-igw" }
}

# --- Management subnet: public (route to IGW), bastion only ---
resource "aws_subnet" "management" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.management_cidr
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = { Name = "${var.lab_name}-management-subnet" }
}

resource "aws_route_table" "management" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "${var.lab_name}-management-rt" }
}

resource "aws_route_table_association" "management" {
  subnet_id      = aws_subnet.management.id
  route_table_id = aws_route_table.management.id
}

# --- Per-domain subnets: private. No route to the IGW; their default route
#     goes through the bastion ENI, which NATs their egress (the bastion is the
#     only host with a public IP, same posture as Azure/Proxmox). This keeps the
#     Windows hosts private-IP-only while still letting the user_data bootstrap
#     reach the internet (it fetches Ansible's ConfigureRemotingForAnsible.ps1),
#     without a paid NAT Gateway — the cost-minimising choice (invariant #4). ---
resource "aws_subnet" "domain" {
  for_each = var.domains

  vpc_id            = aws_vpc.vpc.id
  cidr_block        = each.value.subnet_cidr
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = { Name = "${var.lab_name}-${replace(each.key, ".", "-")}-subnet" }
}

resource "aws_route_table" "domain" {
  for_each = var.domains

  vpc_id = aws_vpc.vpc.id

  # Egress NATed through the bastion's ENI (source/dest check disabled on it —
  # see bastion.tf). The bastion's cloud-init masquerades this traffic out to
  # the internet gateway.
  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = aws_network_interface.bastion.id
  }

  tags = { Name = "${var.lab_name}-${replace(each.key, ".", "-")}-rt" }
}

resource "aws_route_table_association" "domain" {
  for_each = var.domains

  subnet_id      = aws_subnet.domain[each.key].id
  route_table_id = aws_route_table.domain[each.key].id
}

# --- Bastion SG: only the WireGuard UDP port from the internet (and, opt-in via
#     bastion_ssh_allowed_cidrs, direct SSH for troubleshooting). Egress open so
#     the bastion can fetch packages and NAT the private subnets out. ---
resource "aws_security_group" "management" {
  name        = "${var.lab_name}-management-sg"
  description = "PurpleForge bastion: WireGuard in, egress out. Only routable host."
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "WireGuard"
    from_port   = var.wireguard_port
    to_port     = var.wireguard_port
    protocol    = "udp"
    cidr_blocks = var.wireguard_allowed_cidrs
  }

  dynamic "ingress" {
    for_each = length(var.bastion_ssh_allowed_cidrs) > 0 ? [1] : []
    content {
      description = "Direct SSH (opt-in troubleshooting)"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.bastion_ssh_allowed_cidrs
    }
  }

  # NAT return traffic + package fetches: the private subnets' egress is
  # forwarded through this instance, so it must accept the forwarded flows back.
  ingress {
    description = "Forwarded egress from the private domain subnets (NAT)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.supernet]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.lab_name}-management-sg" }
}

# --- Per-domain SG: inbound only from the bastion SG (i.e. only reachable
#     through the WireGuard tunnel) and from peers in the same domain (AD
#     replication/auth); egress open (NATed via the bastion). No internet
#     ingress is possible — no rule admits it and no host has a public IP. ---
resource "aws_security_group" "domain" {
  for_each = var.domains

  name        = "${var.lab_name}-${replace(each.key, ".", "-")}-sg"
  description = "PurpleForge ${each.key}: in from bastion + same-domain only."
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description     = "All from the management/bastion subnet"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.management.id]
  }

  ingress {
    description = "Intra-domain (AD replication/auth)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.lab_name}-${replace(each.key, ".", "-")}-sg" }
}

data "aws_availability_zones" "available" {
  state = "available"
}

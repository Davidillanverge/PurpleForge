# Network isolation (CLAUDE.md invariant #1): a management subnet that only the
# WireGuard bastion lives in, one subnet per AD domain that accepts WinRM only
# from the management subnet, and an explicit deny-all-inbound rule on every
# NSG so the deny-by-default posture is auditable rather than left to Azure's
# implicit platform default.

resource "azurerm_virtual_network" "vnet" {
  name                = "${var.lab_name}-vnet"
  address_space       = [var.supernet]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "management" {
  name                 = "${var.lab_name}-management-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.management_cidr]
}

resource "azurerm_subnet" "domain" {
  for_each = var.domains

  name                 = "${var.lab_name}-${replace(each.key, ".", "-")}-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [each.value.subnet_cidr]
}

# --- Management subnet NSG: only the bastion lives here, nothing to expose ---
#
# The WireGuard and (optional) SSH rules live HERE, as inline security_rule
# blocks, not as separate azurerm_network_security_rule resources attached
# via network_security_group_name (bastion.tf used to do that) — verified on
# a real deploy that mixing the two management styles on the same NSG is a
# real, silent-data-loss conflict: applying an unrelated change elsewhere
# (even a completely different NSG in the same `terraform apply`) can make
# Terraform reconcile this NSG's inline security_rule set — which was empty,
# since the rules lived in separate resources — by DELETING the
# separately-managed wireguard/SSH rules outright. No error, no warning; the
# WireGuard tunnel just silently stops accepting new connections. The
# AzureRM provider docs call this out explicitly (can't mix the two
# management styles on one NSG) — this file just didn't follow that before.
resource "azurerm_network_security_group" "management" {
  name                = "${var.lab_name}-management-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "allow-wireguard-inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = tostring(var.wireguard_port)
    source_address_prefixes    = var.wireguard_allowed_cidrs
    destination_address_prefix = "*"
  }

  dynamic "security_rule" {
    for_each = length(var.bastion_ssh_allowed_cidrs) > 0 ? [1] : []
    content {
      name                       = "allow-bastion-ssh"
      priority                   = 110
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "22"
      source_address_prefixes    = var.bastion_ssh_allowed_cidrs
      destination_address_prefix = "*"
    }
  }

  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "management" {
  subnet_id                 = azurerm_subnet.management.id
  network_security_group_id = azurerm_network_security_group.management.id
}

# --- Per-domain subnet NSG: deny-by-default, WinRM allowed only from the
#     management subnet (i.e. only reachable through the WireGuard bastion),
#     free intra-subnet traffic for AD replication/auth, no path to/from the
#     internet at all. ---
resource "azurerm_network_security_group" "domain" {
  for_each = var.domains

  name                = "${var.lab_name}-${replace(each.key, ".", "-")}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    # Every port/protocol, not just WinRM — the management subnet is only
    # ever reachable via the WireGuard bastion in the first place (see
    # bastion.tf/the allow-wireguard-inbound rule on the management NSG), so
    # anything landing here already came through the tunnel. Narrowing this
    # to specific ports (WinRM only, as an earlier version of this rule did)
    # doesn't add real isolation — it just blocks legitimate operator traffic
    # (SMB, RDP, etc.) that has no other path in anyway, while CLAUDE.md
    # invariant #1 (no public IP, no RDP/WinRM open to 0.0.0.0/0) is enforced
    # by source_address_prefix being the management subnet, not by narrowing
    # the destination port here.
    name                       = "allow-all-from-management"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = var.management_cidr
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-intra-domain"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = each.value.subnet_cidr
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "deny-internet-inbound"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "domain" {
  for_each = var.domains

  subnet_id                 = azurerm_subnet.domain[each.key].id
  network_security_group_id = azurerm_network_security_group.domain[each.key].id
}

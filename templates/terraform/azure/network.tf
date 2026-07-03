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
resource "azurerm_network_security_group" "management" {
  name                = "${var.lab_name}-management-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

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
    name                       = "allow-winrm-from-management"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["5985", "5986"]
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

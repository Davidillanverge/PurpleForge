# Windows VM shape follows vendor/GOAD/template/provider/azure/windows.tf
# (azurerm_windows_virtual_machine + CustomScriptExtension running Ansible's
# own ConfigureRemotingForAnsible.ps1) but every NIC here is private-IP-only —
# no azurerm_public_ip is ever attached to a Windows host. WinRM is reachable
# solely from the management subnet via the NSG rule in network.tf, i.e. only
# through the WireGuard bastion.

locals {
  # SKU names follow vendor/GOAD/ad/GOAD/providers/azure/windows.tf's
  # convention (publisher "MicrosoftWindowsServer", offer "WindowsServer",
  # e.g. "2019-Datacenter"). 2022/2025 and the client SKUs are best-effort —
  # verify with `az vm image list --publisher <p> --offer <o> --all -o table`
  # before a real deploy, per GOAD's own comment in that file.
  os_image_map = {
    "windows-server-2016" = { publisher = "MicrosoftWindowsServer", offer = "WindowsServer", sku = "2016-Datacenter" }
    "windows-server-2019" = { publisher = "MicrosoftWindowsServer", offer = "WindowsServer", sku = "2019-Datacenter" }
    "windows-server-2022" = { publisher = "MicrosoftWindowsServer", offer = "WindowsServer", sku = "2022-Datacenter" }
    "windows-server-2025" = { publisher = "MicrosoftWindowsServer", offer = "WindowsServer", sku = "2025-Datacenter" }
    "windows-10-22h2"     = { publisher = "MicrosoftWindowsDesktop", offer = "Windows-10", sku = "win10-22h2-pro" }
    "windows-11-23h2"     = { publisher = "MicrosoftWindowsDesktop", offer = "Windows-11", sku = "win11-23h2-pro" }
  }

  size_map = {
    "domain-controller" = "Standard_B2s"
    "member-server"     = "Standard_B2ms"
    "workstation"       = "Standard_B2s"
  }

  machines_by_name = { for m in var.machines : m.name => m }
}

resource "azurerm_network_interface" "windows" {
  for_each = local.machines_by_name

  name                = "${var.lab_name}-${each.value.name}-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.domain[each.value.domain].id
    private_ip_address_allocation = "Static"
    private_ip_address            = each.value.ip
  }
}

resource "azurerm_windows_virtual_machine" "windows" {
  for_each = local.machines_by_name

  name                = each.value.name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  size                = local.size_map[each.value.role]
  admin_username      = var.admin_username
  admin_password      = var.admin_password
  network_interface_ids = [
    azurerm_network_interface.windows[each.key].id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  # source_image_id and source_image_reference are mutually exclusive in
  # azurerm_windows_virtual_machine — machines[].image_id (a managed image or
  # Shared Image Gallery version resource ID, e.g. a golden workstation image
  # with an EDR agent pre-installed) overrides the marketplace publisher/
  # offer/sku lookup for os when set. `os` is still required either way — it
  # still drives which ansible-lockdown role/OS-specific Ansible behavior
  # applies downstream, independent of which image backs the VM.
  source_image_id = each.value.image_id

  dynamic "source_image_reference" {
    for_each = each.value.image_id == null ? [1] : []
    content {
      publisher = local.os_image_map[each.value.os].publisher
      offer     = local.os_image_map[each.value.os].offer
      sku       = local.os_image_map[each.value.os].sku
      version   = "latest"
    }
  }
}

resource "azurerm_virtual_machine_extension" "winrm_prep" {
  for_each = local.machines_by_name

  name                 = "${each.value.name}-ansible-prep"
  virtual_machine_id   = azurerm_windows_virtual_machine.windows[each.key].id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.9"

  settings = jsonencode({
    fileUris         = ["https://raw.githubusercontent.com/ansible/ansible/38e50c9f819a045ea4d40068f83e78adbfaf2e68/examples/scripts/ConfigureRemotingForAnsible.ps1"]
    commandToExecute = "net user ansible ${var.ansible_password} /add /expires:never /y && net localgroup administrators ansible /add && powershell -ExecutionPolicy Unrestricted -File ConfigureRemotingForAnsible.ps1"
  })
}

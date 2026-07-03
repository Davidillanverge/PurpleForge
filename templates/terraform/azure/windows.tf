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
  #
  # windows-11-23h2 deliberately maps to the "-avd" SKU, not "-pro": verified
  # against a real deploy that MicrosoftWindowsDesktop/Windows-11/win11-23h2-pro
  # has ZERO published image versions in every region checked (northeurope,
  # westeurope, eastus, westus2, francecentral, germanywestcentral, uksouth,
  # switzerlandnorth, swedencentral) regardless of Microsoft.MarketplaceOrdering
  # agreement acceptance — standalone Windows 11 client OS isn't offered as a
  # plain IaaS image outside Azure Virtual Desktop/Windows 365 or a Visual
  # Studio subscription benefit. "-avd" is the same OS build and the only
  # win11-23h2 plan with real image versions; it deploys as an ordinary
  # standalone VM here (no AVD host pool involved). windows-10-22h2 keeps
  # "-pro" since MicrosoftWindowsDesktop/Windows-10/win10-22h2-pro DOES have
  # published versions and needs no such substitution.
  #
  # Every windows-server-* maps to its Hyper-V Generation 2 SKU, not the
  # bare "<year>-Datacenter": verified against a real deploy that newer VM
  # size families (e.g. Fasv7, used when var.vm_size_overrides picks a size
  # to fit a subscription's low regional core quota) are Gen2-only and
  # reject a Gen1 SKU outright ("cannot boot Hypervisor Generation '1'",
  # https://aka.ms/azuregen2vm). Gen2 images run on both Gen1- and
  # Gen2-capable sizes, so this is a strict widening, not a narrowing, of
  # which vm_size_overrides values work. **The Gen2 SKU suffix is NOT
  # consistent across Windows Server versions** — verified by listing
  # Microsoft.Compute/locations/<region>/publishers/MicrosoftWindowsServer/
  # artifacttypes/vmimage/offers/WindowsServer/skus directly (not `az vm
  # image list`, broken in some environments — see AZURE-DEPLOY-RUNBOOK.md):
  # 2016/2019 use "-gensecond" ("2016-datacenter-gensecond"), 2022/2025 use
  # "-g2" ("2022-datacenter-g2"). Don't assume one pattern for a new OS
  # entry without checking that same listing first.
  os_image_map = {
    "windows-server-2016" = { publisher = "MicrosoftWindowsServer", offer = "WindowsServer", sku = "2016-datacenter-gensecond" }
    "windows-server-2019" = { publisher = "MicrosoftWindowsServer", offer = "WindowsServer", sku = "2019-datacenter-gensecond" }
    "windows-server-2022" = { publisher = "MicrosoftWindowsServer", offer = "WindowsServer", sku = "2022-datacenter-g2" }
    "windows-server-2025" = { publisher = "MicrosoftWindowsServer", offer = "WindowsServer", sku = "2025-datacenter-g2" }
    "windows-10-22h2"     = { publisher = "MicrosoftWindowsDesktop", offer = "Windows-10", sku = "win10-22h2-pro" }
    "windows-11-23h2"     = { publisher = "MicrosoftWindowsDesktop", offer = "Windows-11", sku = "win11-23h2-avd" }
  }

  size_map = merge({
    "domain-controller" = "Standard_B2s"
    "member-server"     = "Standard_B2ms"
    "workstation"       = "Standard_B2s"
  }, var.vm_size_overrides)

  machines_by_name = { for m in var.machines : m.name => m }

  # MicrosoftWindowsDesktop client-OS images (Windows 10/11) are marketplace
  # offers gated behind a per-publisher/offer/plan Microsoft.MarketplaceOrdering
  # agreement — verified on a real deploy that VM creation 404s with
  # PlatformImageNotFound (not a clearer "terms not accepted" error) until
  # that agreement is accepted, and that this is unrelated to the `plan`
  # block above (see its comment). WindowsServer images are first-party and
  # need no agreement. Keyed by os (not by sku) and only for os values
  # actually used by a machine in this spec, so a lab with only server roles
  # creates zero of these.
  client_os_agreements = {
    for os in toset([for m in var.machines : m.os if local.os_image_map[m.os].publisher == "MicrosoftWindowsDesktop"]) :
    os => local.os_image_map[os]
  }
}

resource "azurerm_marketplace_agreement" "client_os" {
  for_each = local.client_os_agreements

  publisher = each.value.publisher
  offer     = each.value.offer
  plan      = each.value.sku
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

  # No `plan` block: verified against a real deploy that Azure rejects one
  # here ("ResourcePurchaseValidationFailed: ... doesn't require plan
  # information") even for the MicrosoftWindowsDesktop client-OS images once
  # their Microsoft.MarketplaceOrdering agreement is accepted — unlike true
  # third-party marketplace offers, these first-party Microsoft images need
  # only the agreement acceptance (azurerm_marketplace_agreement.client_os
  # above), not a `plan` block on the VM resource itself.

  depends_on = [azurerm_marketplace_agreement.client_os]
}

resource "azurerm_virtual_machine_extension" "winrm_prep" {
  for_each = local.machines_by_name

  name                 = "${each.value.name}-ansible-prep"
  virtual_machine_id   = azurerm_windows_virtual_machine.windows[each.key].id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.9"

  settings = jsonencode({
    fileUris = ["https://raw.githubusercontent.com/ansible/ansible/38e50c9f819a045ea4d40068f83e78adbfaf2e68/examples/scripts/ConfigureRemotingForAnsible.ps1"]
    # The extra New-NetFirewallRule call fixes a real deploy-time gotcha
    # ConfigureRemotingForAnsible.ps1 does not handle: every Azure Windows VM
    # NIC comes up with NetworkCategory "Public" (never auto-promoted to
    # "Private", since there is no AD domain yet at this point in the deploy
    # sequence), and the *built-in* "Windows Remote Management (HTTP-In)"
    # rule's Public-profile instance is scoped to RemoteAddress=LocalSubnet —
    # verified against a real deploy that this silently blocks WinRM from any
    # host outside the target's own subnet (e.g. the bastion, which always
    # lives in a separate management subnet — see network.tf) while
    # same-subnet WinRM traffic works fine, with no NSG or WinRM-service-level
    # symptom at all. Scoped to the lab's own supernet, not "Any" — WinRM
    # still never reaches the internet (invariant #1), it just also becomes
    # reachable from other subnets inside this one lab's VNet.
    commandToExecute = "net user ansible ${var.ansible_password} /add /expires:never /y && net localgroup administrators ansible /add && powershell -ExecutionPolicy Unrestricted -File ConfigureRemotingForAnsible.ps1 && powershell -Command \"New-NetFirewallRule -DisplayName 'PurpleForge-WinRM-VNet' -Direction Inbound -Protocol TCP -LocalPort 5985,5986 -RemoteAddress ${var.supernet} -Action Allow -Profile Any\""
  })
}

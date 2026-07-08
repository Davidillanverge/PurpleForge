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
  # standalone VM here (no AVD host pool involved). windows-10-22h2 uses the
  # Gen2 "win10-22h2-pro-g2" SKU (not the Gen1 "win10-22h2-pro"): both have
  # published versions, but the Gen1 SKU cannot boot a Gen2-only VM size
  # ("cannot boot Hypervisor Generation '1'"), and the newer size families
  # some subscriptions are restricted to (Fasv7 etc.) are Gen2-only.
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
  #
  # DISK CONTROLLER caveat: the Fasv7/Dsv7/Esv7 families some restricted
  # subscriptions only offer are NVMe-*only* (DiskControllerTypes=NVMe), and
  # an image must declare NVMe support to boot on them. Verified via the
  # image version's `features`: windows-server-2019/2022/2025 and
  # win10-22h2-pro-g2/win11-23h2 report "SCSI, NVMe", but
  # windows-server-2016-gensecond reports "SCSI" only — so a 2016 DC cannot
  # run on an NVMe-only size at all (no Gen2 SKU fixes it; it's the guest
  # image, not the hypervisor generation). Pick 2019+ for such subscriptions.
  # var.custom_os_images (set at deploy time from PF_IMAGE_PUBLISHER/OFFER/SKU)
  # is merged LAST so a deployer can add a Windows image PurpleForge ships no
  # mapping for, or override a built-in entry, without editing this file.
  os_image_map = merge({
    "windows-server-2016" = { publisher = "MicrosoftWindowsServer", offer = "WindowsServer", sku = "2016-datacenter-gensecond" }
    "windows-server-2019" = { publisher = "MicrosoftWindowsServer", offer = "WindowsServer", sku = "2019-datacenter-gensecond" }
    "windows-server-2022" = { publisher = "MicrosoftWindowsServer", offer = "WindowsServer", sku = "2022-datacenter-g2" }
    "windows-server-2025" = { publisher = "MicrosoftWindowsServer", offer = "WindowsServer", sku = "2025-datacenter-g2" }
    "windows-10-22h2"     = { publisher = "MicrosoftWindowsDesktop", offer = "Windows-10", sku = "win10-22h2-pro-g2" }
    "windows-11-23h2"     = { publisher = "MicrosoftWindowsDesktop", offer = "Windows-11", sku = "win11-23h2-avd" }
  }, var.custom_os_images)

  size_map = merge({
    "domain-controller" = "Standard_B2s"
    "member-server"     = "Standard_B2ms"
    "workstation"       = "Standard_B2s"
  }, var.vm_size_overrides)

  machines_by_name = { for m in var.machines : m.name => m }

  # Effective backing image per machine, resolving the deploy-time overrides
  # (var.os_overrides / var.image_id_overrides, written by deploy.sh from
  # PF_OS / PF_IMAGE_ID) against the values baked into machines[] at generate
  # time. Precedence, most specific first:
  #   image_id : per-machine machines[].image_id pin  >  per-role image_id_overrides
  #   os       : per-role os_overrides                 >  per-machine machines[].os
  # A resolved image_id wins over any os (source_image_id and a marketplace
  # source_image_reference are mutually exclusive — see the VM resource below).
  # Not coalesce(): it errors when BOTH are null (the common no-override case),
  # but null is exactly what we need there to fall through to the marketplace
  # source_image_reference below.
  effective_image_id = {
    for k, m in local.machines_by_name :
    k => m.image_id != null ? m.image_id : lookup(var.image_id_overrides, m.role, null)
  }
  effective_os = {
    for k, m in local.machines_by_name :
    k => lookup(var.os_overrides, m.role, m.os)
  }

  # MicrosoftWindowsDesktop client-OS images (Windows 10/11) are marketplace
  # offers gated behind a per-publisher/offer/plan Microsoft.MarketplaceOrdering
  # agreement — verified on a real deploy that VM creation 404s with
  # PlatformImageNotFound (not a clearer "terms not accepted" error) until
  # that agreement is accepted, and that this is unrelated to the `plan`
  # block above (see its comment). WindowsServer images are first-party and
  # need no agreement. Keyed by os (not by sku) and only for os values
  # actually used by a machine in this spec, so a lab with only server roles
  # creates zero of these.
  # Keyed on the EFFECTIVE os (after os_overrides), and only for hosts that
  # actually land on a marketplace image (no resolved image_id), so a PF_OS
  # that swaps a server lab onto a client SKU still accepts the right agreement,
  # and an image_id override needs none.
  client_os_agreements = {
    for os in toset([
      for k, m in local.machines_by_name :
      local.effective_os[k]
      if local.effective_image_id[k] == null && local.os_image_map[local.effective_os[k]].publisher == "MicrosoftWindowsDesktop"
    ]) :
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
  # Per-machine spec override (machines[].vm_size) wins; otherwise the per-role
  # default map (itself overridable wholesale by var.vm_size_overrides).
  size                = coalesce(each.value.vm_size, local.size_map[each.value.role])
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
  # azurerm_windows_virtual_machine — a resolved image_id (machines[].image_id
  # pin or the deploy-time image_id_overrides, e.g. a golden image with an EDR
  # agent pre-installed) overrides the marketplace publisher/offer/sku lookup.
  # The effective os (baked machines[].os, possibly replaced by the deploy-time
  # os_overrides) still drives which ansible-lockdown role/OS-specific Ansible
  # behavior applies downstream, independent of which image backs the VM.
  source_image_id = local.effective_image_id[each.key]

  dynamic "source_image_reference" {
    for_each = local.effective_image_id[each.key] == null ? [1] : []
    content {
      publisher = local.os_image_map[local.effective_os[each.key]].publisher
      offer     = local.os_image_map[local.effective_os[each.key]].offer
      sku       = local.os_image_map[local.effective_os[each.key]].sku
      version   = var.image_version_override
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
    # The password MUST be double-quoted here: it runs under cmd.exe, where an
    # unquoted `&`/`^`/`<`/`>`/`|` in the password is a command separator (a `&`
    # split `net user` mid-command and the tail ran as a bogus command, so the
    # ansible user was never created and WinRM never came up). Quotes make those
    # literal. generate_password also excludes cmd-hostile chars as belt-and-braces.
    commandToExecute = "net user ansible \"${var.ansible_password}\" /add /expires:never /y && net localgroup administrators ansible /add && powershell -ExecutionPolicy Unrestricted -File ConfigureRemotingForAnsible.ps1 && powershell -Command \"New-NetFirewallRule -DisplayName 'PurpleForge-WinRM-VNet' -Direction Inbound -Protocol TCP -LocalPort 5985,5986 -RemoteAddress ${var.supernet} -Action Allow -Profile Any\""
  })
}

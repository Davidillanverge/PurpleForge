# CLAUDE.md invariant #4: every deployment carries auto_shutdown. Applies to
# every VM in the lab (bastion included — it's what's billed, same as the
# Windows hosts) via Azure's native DevTest auto-shutdown schedule, so cost
# doesn't depend on anyone remembering to run `/destroy` promptly.

resource "azurerm_dev_test_global_vm_shutdown_schedule" "bastion" {
  virtual_machine_id    = azurerm_linux_virtual_machine.bastion.id
  location              = azurerm_resource_group.rg.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone

  notification_settings {
    enabled = false
  }
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "windows" {
  for_each = local.machines_by_name

  virtual_machine_id    = azurerm_windows_virtual_machine.windows[each.key].id
  location              = azurerm_resource_group.rg.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone

  notification_settings {
    enabled = false
  }
}

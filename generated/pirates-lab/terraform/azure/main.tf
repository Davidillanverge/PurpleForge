resource "azurerm_resource_group" "rg" {
  name     = var.lab_name
  location = var.location

  tags = {
    lab     = var.lab_name
    project = "purpleforge"
  }
}

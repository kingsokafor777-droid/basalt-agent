resource "azurerm_storage_account" "exports" {
  name                            = "customerexportprod"
  resource_group_name             = "security"
  location                        = "eastus"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
}

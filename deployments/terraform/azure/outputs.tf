output "audit_export_client_id" {
  description = "Annotate the audit export service account with azure.workload.identity/client-id = this value"
  value       = azurerm_user_assigned_identity.audit_export.client_id
}

output "key_vault_uri" {
  description = "Key Vault holding the database URL, audit key and upstream credentials"
  value       = azurerm_key_vault.gateway.vault_uri
}

output "audit_container" {
  description = "Immutable blob container receiving exported audit segments"
  value       = "${azurerm_storage_account.audit.name}/${azurerm_storage_container.audit.name}"
}

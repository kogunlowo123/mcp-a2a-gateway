output "audit_export_role_arn" {
  description = "Annotate the audit export service account with eks.amazonaws.com/role-arn = this value"
  value       = aws_iam_role.audit_export.arn
}

output "database_url_secret_name" {
  description = "Secrets Manager secret synced to Kubernetes as DATABASE_URL"
  value       = aws_secretsmanager_secret.database_url.name
}

output "kms_key_arn" {
  description = "KMS key that encrypts the database, secrets and audit bucket; use it for signing-key secrets"
  value       = aws_kms_key.gateway.arn
}

output "audit_bucket" {
  description = "Object Lock (compliance mode) bucket receiving exported audit segments"
  value       = aws_s3_bucket.audit.bucket
}

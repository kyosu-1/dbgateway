output "public_url" {
  description = "dbgateway's server.public_url: Cloud Run's deterministic URL"
  value       = local.public_url
}

output "service_uri" {
  description = "The service's uri attribute as reported by Cloud Run (null until the service is created); usually the https://<name>-<hash>.a.run.app form"
  value       = one(google_cloud_run_v2_service.this[*].uri)
}

output "service_urls" {
  description = "All URLs Cloud Run assigned to the service (null until it is created); should include public_url"
  value       = one(google_cloud_run_v2_service.this[*].urls)
}

output "artifact_repository" {
  description = "Image path prefix, e.g. <artifact_repository>/dbgateway:<tag>"
  value       = local.artifact_repository
}

output "service_account_email" {
  value = google_service_account.run.email
}

output "iam_db_user" {
  description = "Cloud SQL IAM database user of the Cloud Run service account (read_user and write_user)"
  value       = google_sql_user.iam.name
}

output "sql_instance_name" {
  value = google_sql_database_instance.this.name
}

output "sql_public_ip" {
  description = "Public IP (reachable only from allowed_cidr; for setup.sh)"
  value       = google_sql_database_instance.this.public_ip_address
}

output "sql_private_ip" {
  description = "Private IP (used by Cloud Run)"
  value       = google_sql_database_instance.this.private_ip_address
}

output "server_ca_cert" {
  description = "PEM of the instance's server CA, for sslrootcert with sslmode=verify-ca"
  value       = google_sql_database_instance.this.server_ca_cert[0].cert
  sensitive   = true # the provider marks server_ca_cert sensitive; the CA is public data
}

output "admin_password" {
  description = "Password of dbgw_admin (used only by setup.sh)"
  value       = random_password.admin.result
  sensitive   = true
}

output "store_password" {
  description = "Password of dbgw_store (owner of the management database)"
  value       = random_password.store.result
  sensitive   = true
}

output "store_dsn_public" {
  description = "Management database DSN over the public IP, for dbgw commands run from allowed_cidr (pass the CA with DBGW_DB_CA)"
  value       = "postgres://${google_sql_user.store.name}:${random_password.store.result}@${google_sql_database_instance.this.public_ip_address}:5432/${google_sql_database.dbgateway.name}?sslmode=verify-ca"
  sensitive   = true
}

output "dbgateway_config" {
  description = "The rendered dbgateway configuration (DBGW_CONFIG_YAML; contains no secrets)"
  value       = local.dbgateway_config
}

output "requester_email" {
  value = var.requester_email
}

output "approver_email" {
  value = var.approver_email
}

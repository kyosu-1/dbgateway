output "instance_name" {
  value = google_sql_database_instance.this.name
}

output "connection_name" {
  description = "Instance connection name (project:region:instance)"
  value       = google_sql_database_instance.this.connection_name
}

output "public_ip" {
  description = "Public IP address (reachable only from allowed_cidr)"
  value       = google_sql_database_instance.this.public_ip_address
}

output "server_ca_cert" {
  description = "PEM of the instance's server CA, for sslrootcert with sslmode=verify-ca"
  value       = google_sql_database_instance.this.server_ca_cert[0].cert
}

output "iam_db_user" {
  description = "Database user name for IAM authentication (read_user with auth: gcp_iam)"
  value       = google_sql_user.iam.name
}

output "admin_password" {
  description = "Password of dbgw_admin (used only by setup.sh)"
  value       = random_password.admin.result
  sensitive   = true
}

output "reader_password" {
  description = "Password for the dbgw_reader user created by setup.sh"
  value       = random_password.reader.result
  sensitive   = true
}

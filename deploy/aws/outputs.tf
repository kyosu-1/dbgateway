output "host" {
  description = "RDS endpoint host name"
  value       = aws_db_instance.this.address
}

output "port" {
  value = aws_db_instance.this.port
}

output "admin_password" {
  description = "Master password (used only to create the read-only user)"
  value       = random_password.master.result
  sensitive   = true
}

output "reader_password" {
  description = "Password for the dbgw_reader user created by setup.sh"
  value       = random_password.reader.result
  sensitive   = true
}

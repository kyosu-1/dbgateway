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

output "region" {
  value = var.region
}

output "iam_auth" {
  description = "Whether IAM database authentication is enabled"
  value       = var.iam_auth
}

output "iam_db_user" {
  description = "Database user for IAM authentication (created by setup.sh)"
  value       = var.iam_auth ? "dbgw_iam" : ""
}

output "iam_connect_policy" {
  description = "IAM policy allowing the dbgw_iam login. Attach it to the identity dbgateway runs as (administrators already have it)."
  value = var.iam_auth ? jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "rds-db:connect"
      Resource = "arn:${data.aws_partition.current.partition}:rds-db:${var.region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.this.resource_id}/dbgw_iam"
    }]
  }) : ""
}

output "region" {
  description = "AWS region"
  value       = var.region
}

output "alb_dns_name" {
  description = "DNS name of the ALB; resolve var.hostname to it on the test client"
  value       = aws_lb.this.dns_name
}

output "hostname" {
  description = "Host name of dbgateway (TLS server name and server.public_url host)"
  value       = var.hostname
}

output "public_url" {
  description = "server.public_url of dbgateway"
  value       = local.public_url
}

output "tls_cert_pem" {
  description = "Self-signed ALB certificate; trust it on the test client"
  value       = tls_self_signed_cert.alb.cert_pem
}

output "requester_email" {
  description = "Member of the developers group (querier, writer)"
  value       = var.requester_email
}

output "approver_email" {
  description = "Member of the approvers group (querier, writer, approver)"
  value       = var.approver_email
}

output "ecr_repository_url" {
  description = "ECR repository for the dbgateway image (linux/arm64)"
  value       = aws_ecr_repository.this.repository_url
}

output "rds_host" {
  description = "RDS endpoint host name (target database app and management database dbgateway)"
  value       = aws_db_instance.this.address
}

output "dbgateway_config" {
  description = "Rendered dbgateway configuration (DBGW_CONFIG_YAML; contains no secrets)"
  value       = local.dbgateway_config
}

output "admin_password" {
  description = "RDS master password (user dbgw_admin; used only by setup.sh)"
  value       = random_password.master.result
  sensitive   = true
}

output "store_password" {
  description = "Password of the management database owner dbgw_store (created by setup.sh)"
  value       = random_password.store.result
  sensitive   = true
}

output "store_dsn" {
  description = "Management database DSN (the same host works from allowed_cidr); set DBGW_DB_CA for sslrootcert_env"
  value       = local.store_dsn
  sensitive   = true
}

output "cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.this.name
}

output "service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.this.name
}

output "log_group" {
  description = "CloudWatch log group of the dbgateway tasks"
  value       = aws_cloudwatch_log_group.this.name
}

# A disposable deployment of dbgateway on Amazon ECS (Fargate) behind an
# internet-facing ALB, with Amazon RDS for PostgreSQL as both the target
# database (IAM database authentication) and the shared management database.
#
# Not a production deployment: the ALB and RDS are reachable only from
# `allowed_cidr`, the ALB uses a self-signed certificate, and everything is
# destroyed without snapshots. See README.md in this directory.

terraform {
  required_version = ">= 1.9"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 6.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
    tls    = { source = "hashicorp/tls", version = "~> 4.0" }
    http   = { source = "hashicorp/http", version = "~> 3.4" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "dbgateway", Purpose = "test", ManagedBy = "terraform" }
  }
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  # Database users created by setup.sh (logins with RDS IAM tokens).
  iam_read_user  = "dbgw_iam"
  iam_write_user = "dbgw_iam_writer"
  store_user     = "dbgw_store"
  store_db       = "dbgateway"
  target_db      = "app"
  gateway_db     = "cloud-main" # dbgateway's name for the target database

  public_url = "https://${var.hostname}"

  # Secret-free configuration; the store DSN comes from Secrets Manager.
  dbgateway_config = templatefile("${path.module}/templates/dbgateway.yaml.tftpl", {
    public_url      = local.public_url
    db_name         = local.gateway_db
    rds_host        = aws_db_instance.this.address
    target_db       = local.target_db
    region          = var.region
    read_user       = local.iam_read_user
    write_user      = local.iam_write_user
    requester_email = var.requester_email
    approver_email  = var.approver_email
  })

  store_dsn = "postgres://${local.store_user}:${random_password.store.result}@${aws_db_instance.this.address}:${aws_db_instance.this.port}/${local.store_db}?sslmode=verify-full"
}

# One RDS for PostgreSQL instance serves both databases:
#   app       - the target database (sample schema; IAM users dbgw_iam and
#               dbgw_iam_writer), created by RDS and loaded by setup.sh
#   dbgateway - the management database and audit log (owner dbgw_store),
#               created by setup.sh
# A production deployment keeps the management database on a separate
# instance (docs/ha.md); one instance keeps this test environment cheap.

resource "random_password" "master" {
  length  = 32
  special = false
}

resource "random_password" "store" {
  length  = 32
  special = false # used verbatim in the store DSN (URL)
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.name}-public"
  subnet_ids = aws_subnet.public[*].id
}

resource "aws_db_parameter_group" "this" {
  name   = "${var.name}-pg17"
  family = "postgres17"

  # Refuse unencrypted connections.
  parameter {
    name  = "rds.force_ssl"
    value = "1"
    # RDS reports this static parameter as pending-reboot; declaring it
    # avoids a perpetual diff (new instances start with it applied).
    apply_method = "pending-reboot"
  }
}

resource "aws_db_instance" "this" {
  identifier             = var.name
  engine                 = "postgres"
  engine_version         = var.engine_version
  instance_class         = var.instance_class
  allocated_storage      = 20
  storage_type           = "gp3"
  storage_encrypted      = true
  db_name                = local.target_db
  username               = "dbgw_admin"
  password               = random_password.master.result
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.this.name
  # Signed by a CA in the regional RDS bundle that the tasks trust.
  ca_cert_identifier = "rds-ca-rsa2048-g1"

  # Publicly addressable so that setup.sh can run from allowed_cidr; the
  # security group admits only allowed_cidr and the dbgateway tasks.
  publicly_accessible = true

  # dbgateway's aws_iam auth: logins with RDS authentication tokens.
  iam_database_authentication_enabled = true

  # Disposable.
  backup_retention_period      = 0
  skip_final_snapshot          = true
  deletion_protection          = false
  delete_automated_backups     = true
  apply_immediately            = true
  performance_insights_enabled = false

  tags = { Name = var.name }
}

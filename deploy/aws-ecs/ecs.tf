# ECR repository, ECS cluster and the dbgateway Fargate service.

locals {
  container_name = "dbgateway"
  container_port = 8443

  # Without an image the service runs no tasks; the task definition still
  # needs an image reference, which is never pulled.
  image        = var.image != "" ? var.image : "${aws_ecr_repository.this.repository_url}:unset"
  task_count   = var.image != "" ? var.desired_count : 0
  rds_ca_url   = "https://truststore.pki.rds.amazonaws.com/${var.region}/${var.region}-bundle.pem"
  rds_ca_certs = trimspace(data.http.rds_ca.response_body)

  rds_dbuser_arn_prefix = "arn:${local.partition}:rds-db:${var.region}:${local.account_id}:dbuser:${aws_db_instance.this.resource_id}"

  container_definitions = jsonencode([{
    name      = local.container_name
    image     = local.image
    essential = true
    # The image's default command reads /etc/dbgateway/dbgateway.yaml;
    # `serve` without --config reads DBGW_CONFIG_YAML instead.
    command = ["serve"]
    portMappings = [{
      containerPort = local.container_port
      protocol      = "tcp"
    }]
    environment = [
      { name = "DBGW_CONFIG_YAML", value = local.dbgateway_config },
      { name = "DBGW_DB_CA", value = local.rds_ca_certs },
    ]
    secrets = [
      { name = "DBGW_STORE_DSN", valueFrom = aws_secretsmanager_secret.store_dsn.arn },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = var.region
        awslogs-stream-prefix = local.container_name
      }
    }
  }])
}

# The RDS CA certificates for this region (the instance's CA is one of
# them). The global bundle (~170 KB) would not fit: an ECS task definition
# is limited to 64 KiB, environment variables included.
data "http" "rds_ca" {
  url = local.rds_ca_url

  lifecycle {
    postcondition {
      condition     = self.status_code == 200 && strcontains(self.response_body, "-----BEGIN CERTIFICATE-----")
      error_message = "Could not download the RDS CA bundle from ${local.rds_ca_url}."
    }
  }
}

resource "aws_ecr_repository" "this" {
  name                 = var.name
  image_tag_mutability = "MUTABLE"
  force_delete         = true # destroy also deletes the pushed images

  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_ecs_cluster" "this" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = "disabled"
  }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = 1
}

# --- Store DSN (the only secret the tasks need) ---

resource "aws_secretsmanager_secret" "store_dsn" {
  name                    = "${var.name}/store-dsn"
  description             = "dbgateway management database DSN (DBGW_STORE_DSN)"
  recovery_window_in_days = 0 # delete immediately on destroy
}

resource "aws_secretsmanager_secret_version" "store_dsn" {
  secret_id     = aws_secretsmanager_secret.store_dsn.id
  secret_string = local.store_dsn
}

# --- IAM ---

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:ecs:${var.region}:${local.account_id}:*"]
    }
  }
}

# Execution role: used by ECS to pull the image, write logs and resolve
# the store DSN secret.
resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # does not support resource-level permissions
  }
  statement {
    sid = "EcrPull"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [aws_ecr_repository.this.arn]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.this.arn}:log-stream:*"]
  }
  statement {
    sid       = "StoreDSN"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.store_dsn.arn]
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "dbgateway-execution"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

# Task role: dbgateway itself. It signs RDS authentication tokens for the
# two IAM database users and needs nothing else.
resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

data "aws_iam_policy_document" "task" {
  statement {
    sid     = "RdsIamLogin"
    actions = ["rds-db:connect"]
    resources = [
      "${local.rds_dbuser_arn_prefix}/${local.iam_read_user}",
      "${local.rds_dbuser_arn_prefix}/${local.iam_write_user}",
    ]
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "dbgateway-rds-connect"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

# --- Task definition and service ---

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  container_definitions    = local.container_definitions

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  lifecycle {
    precondition {
      # The whole task definition must stay under 64 KiB; leave headroom
      # for the fields outside the container definitions.
      condition     = length(local.container_definitions) < 56 * 1024
      error_message = "The container definitions (configuration and CA certificates in environment variables) exceed the ECS task definition size limit."
    }
  }
}

resource "aws_ecs_service" "this" {
  name                              = var.name
  cluster                           = aws_ecs_cluster.this.id
  task_definition                   = aws_ecs_task_definition.this.arn
  desired_count                     = local.task_count
  launch_type                       = "FARGATE"
  platform_version                  = "LATEST"
  health_check_grace_period_seconds = 60
  # Rolling deployments keep at least one task serving.
  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200
  enable_ecs_managed_tags            = true
  propagate_tags                     = "SERVICE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = local.container_name
    container_port   = local.container_port
  }

  depends_on = [
    # The target group must be attached to the ALB before the service uses it.
    aws_lb_listener.https,
    # Tasks need the NAT route, the execution permissions and the secret
    # value at start; keep them until the service is gone on destroy.
    aws_route.private_nat,
    aws_route_table_association.private,
    aws_iam_role_policy.execution,
    aws_iam_role_policy.task,
    aws_secretsmanager_secret_version.store_dsn,
  ]
}

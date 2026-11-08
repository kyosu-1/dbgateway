variable "region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-1"
}

variable "name" {
  description = "Name prefix for the created resources (also the ALB, target group, RDS and ECR names)"
  type        = string
  default     = "dbgw-ecs-test"

  validation {
    # ALB / target group names: at most 32 characters; RDS identifiers start
    # with a letter; ECR names are lowercase.
    condition     = can(regex("^[a-z][a-z0-9-]{0,26}[a-z0-9]$", var.name))
    error_message = "name must be 2-28 lowercase letters, digits or hyphens, start with a letter and not end with a hyphen."
  }
}

variable "allowed_cidr" {
  description = "CIDR allowed to reach the ALB (443) and PostgreSQL (5432), e.g. your public IP as x.x.x.x/32"
  type        = string

  validation {
    condition     = can(cidrhost(var.allowed_cidr, 0)) && var.allowed_cidr != "0.0.0.0/0"
    error_message = "allowed_cidr must be a valid CIDR and must not be 0.0.0.0/0."
  }
}

variable "hostname" {
  description = "Host name of dbgateway (server.public_url and the self-signed certificate). Resolve it to the ALB on the test client yourself."
  type        = string
  default     = "dbgw.test"

  validation {
    # WebAuthn relying party IDs cannot be IP addresses.
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.hostname)) && !can(cidrhost("${var.hostname}/32", 0))
    error_message = "hostname must be a lowercase DNS name with at least one dot (not an IP address)."
  }
}

variable "image" {
  description = "dbgateway container image (linux/arm64) in the ECR repository. Empty: the service runs no tasks, so the repository can be created and the image pushed first."
  type        = string
  default     = ""
}

variable "desired_count" {
  description = "Number of dbgateway tasks when image is set (two prove the shared PostgreSQL management database)"
  type        = number
  default     = 2

  validation {
    condition     = var.desired_count >= 0 && var.desired_count <= 4
    error_message = "desired_count must be between 0 and 4."
  }
}

variable "requester_email" {
  description = "E-mail of the test requester (group developers: querier, writer)"
  type        = string

  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.requester_email))
    error_message = "requester_email must be an e-mail address."
  }
}

variable "approver_email" {
  description = "E-mail of the test approver (group approvers: querier, writer, approver); must differ from requester_email"
  type        = string

  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.approver_email)) && lower(var.approver_email) != lower(var.requester_email)
    error_message = "approver_email must be an e-mail address different from requester_email (nobody approves their own request)."
  }
}

variable "vpc_cidr" {
  description = "CIDR of the new VPC"
  type        = string
  default     = "10.42.0.0/16"

  validation {
    condition     = can(cidrsubnet(var.vpc_cidr, 8, 11))
    error_message = "vpc_cidr must be a valid IPv4 CIDR with room for subnets 8 bits longer (e.g. a /16 split into /24s)."
  }
}

variable "engine_version" {
  description = "PostgreSQL version (match the pg_query_go parser major version)"
  type        = string
  default     = "17"
}

variable "instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.micro"
}

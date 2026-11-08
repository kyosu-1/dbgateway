variable "region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-1"
}

variable "name" {
  description = "Name prefix for the created resources"
  type        = string
  default     = "dbgateway-test"
}

variable "allowed_cidr" {
  description = "CIDR allowed to reach PostgreSQL, e.g. your public IP as x.x.x.x/32"
  type        = string

  validation {
    condition     = can(cidrhost(var.allowed_cidr, 0)) && var.allowed_cidr != "0.0.0.0/0"
    error_message = "allowed_cidr must be a valid CIDR and must not be 0.0.0.0/0."
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

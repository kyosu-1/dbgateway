variable "project" {
  description = "Google Cloud project ID"
  type        = string
}

variable "region" {
  description = "Cloud SQL region"
  type        = string
  default     = "asia-northeast1"
}

variable "name" {
  description = "Name prefix for the instance (a random suffix is appended)"
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

variable "iam_principal" {
  description = "Email of the Google account or service account dbgateway authenticates as (e.g. the output of `gcloud config get account`)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9._%+-]+@[a-z0-9.-]+$", var.iam_principal))
    error_message = "iam_principal must be a lowercase email address."
  }
}

variable "grant_iam_roles" {
  description = "Grant roles/cloudsql.instanceUser and roles/cloudsql.client to iam_principal on the project"
  type        = bool
  default     = true
}

variable "tier" {
  description = "Cloud SQL machine tier (Enterprise edition)"
  type        = string
  default     = "db-f1-micro"
}

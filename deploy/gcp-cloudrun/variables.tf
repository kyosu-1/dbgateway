variable "project" {
  description = "Google Cloud project ID"
  type        = string
}

variable "region" {
  description = "Region for Cloud Run, Cloud SQL, the subnet and Artifact Registry"
  type        = string
  default     = "asia-northeast1"
}

variable "name" {
  description = "Name of the Cloud Run service; prefix of the other resources"
  type        = string
  default     = "dbgw-run-test"

  validation {
    # "<name>-run" must fit a service account ID (6-30 characters); this also
    # keeps "<name>-<project number>" within the 63-character DNS label of
    # Cloud Run's deterministic URL.
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}[a-z0-9]$", var.name))
    error_message = "name must be 4-26 characters of lowercase letters, digits and hyphens, start with a letter and not end with a hyphen."
  }
}

variable "allowed_cidr" {
  description = "CIDR allowed to reach the Cloud SQL public IP (for setup.sh), e.g. your public IP as x.x.x.x/32"
  type        = string

  validation {
    condition     = can(cidrhost(var.allowed_cidr, 0)) && var.allowed_cidr != "0.0.0.0/0"
    error_message = "allowed_cidr must be a valid CIDR and must not be 0.0.0.0/0."
  }
}

variable "invoker" {
  description = "IAM principal granted roles/run.invoker on the service, e.g. user:someone@example.com"
  type        = string

  validation {
    condition     = can(regex("^(user|serviceAccount|group|domain|principal|principalSet):.+", var.invoker)) && !contains(["allUsers", "allAuthenticatedUsers"], var.invoker)
    error_message = "invoker must be an IAM member such as user:someone@example.com (allUsers and allAuthenticatedUsers are not allowed)."
  }
}

variable "image" {
  description = "dbgateway image (linux/amd64) in the Artifact Registry repository; empty: do not create the Cloud Run service yet"
  type        = string
  default     = ""
}

variable "requester_email" {
  description = "E-mail of the requester (group developers: querier, writer)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9._%+-]+@[a-z0-9.-]+$", var.requester_email))
    error_message = "requester_email must be a lowercase e-mail address."
  }
}

variable "approver_email" {
  description = "E-mail of the approver (group approvers: querier, writer, approver)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9._%+-]+@[a-z0-9.-]+$", var.approver_email))
    error_message = "approver_email must be a lowercase e-mail address."
  }
}

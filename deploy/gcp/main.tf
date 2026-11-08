# A disposable Cloud SQL for PostgreSQL 17 instance for testing dbgateway
# against a managed database with TLS and IAM database authentication
# (auth: gcp_iam).
#
# Not a production deployment: the public IP is reachable only from
# `allowed_cidr`, the instance uses a small tier without backups, and it is
# deleted without protection. See README.md in this directory.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 7.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "google" {
  project = var.project
  region  = var.region
}

locals {
  # Cloud SQL IAM users: a service account's database user name is its
  # email without the ".gserviceaccount.com" suffix; a user's is the email.
  iam_is_service_account = endswith(var.iam_principal, ".gserviceaccount.com")
  iam_db_user            = local.iam_is_service_account ? trimsuffix(var.iam_principal, ".gserviceaccount.com") : var.iam_principal
  iam_member             = "${local.iam_is_service_account ? "serviceAccount" : "user"}:${var.iam_principal}"
}

resource "google_project_service" "sqladmin" {
  service            = "sqladmin.googleapis.com"
  disable_on_destroy = false
}

# Instance names cannot be reused for a while after deletion.
resource "random_id" "suffix" {
  byte_length = 3
}

resource "random_password" "admin" {
  length  = 32
  special = false
}

resource "random_password" "reader" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "this" {
  name                = "${var.name}-${random_id.suffix.hex}"
  database_version    = "POSTGRES_17"
  region              = var.region
  deletion_protection = false

  settings {
    # PostgreSQL 16+ defaults to Enterprise Plus; Enterprise allows the
    # small shared-core tiers.
    edition           = "ENTERPRISE"
    tier              = var.tier
    availability_type = "ZONAL"
    disk_size         = 10
    disk_type         = "PD_SSD"

    user_labels = {
      project    = "dbgateway"
      purpose    = "test"
      managed-by = "terraform"
    }

    backup_configuration {
      enabled = false
    }

    ip_configuration {
      ipv4_enabled = true
      # TLS is mandatory, without client certificates (dbgateway connects
      # directly, not through the Cloud SQL Auth Proxy).
      ssl_mode = "ENCRYPTED_ONLY"
      # Per-instance CA: verifying the CA (sslmode=verify-ca) also verifies
      # the server identity.
      server_ca_mode = "GOOGLE_MANAGED_INTERNAL_CA"

      authorized_networks {
        name  = "test-client"
        value = var.allowed_cidr
      }
    }

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }
  }

  depends_on = [google_project_service.sqladmin]
}

resource "google_sql_database" "app" {
  name     = "app"
  instance = google_sql_database_instance.this.name
  # Deleted together with the instance; dropping it first would fail
  # because the sample schema's objects depend on it.
  deletion_policy = "ABANDON"
}

# Built-in administrator, used only by setup.sh to load the sample schema
# (which creates the dbgw_reader password user).
resource "google_sql_user" "admin" {
  name     = "dbgw_admin"
  instance = google_sql_database_instance.this.name
  password = random_password.admin.result
  # It owns the sample schema; it is removed with the instance.
  deletion_policy = "ABANDON"
}

# IAM database user for dbgateway's gcp_iam auth.
resource "google_sql_user" "iam" {
  name     = local.iam_db_user
  instance = google_sql_database_instance.this.name
  type     = local.iam_is_service_account ? "CLOUD_IAM_SERVICE_ACCOUNT" : "CLOUD_IAM_USER"
  # It holds grants in the database; it is removed with the instance.
  deletion_policy = "ABANDON"
}

# roles/cloudsql.instanceUser is required for IAM database logins;
# roles/cloudsql.client only for the Cloud SQL Auth Proxy / connectors (and
# to read the instance metadata). Project owners already have both.
resource "google_project_iam_member" "iam_roles" {
  for_each = var.grant_iam_roles ? toset(["roles/cloudsql.instanceUser", "roles/cloudsql.client"]) : toset([])
  project  = var.project
  role     = each.value
  member   = local.iam_member
}

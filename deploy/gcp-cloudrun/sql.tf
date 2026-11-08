# Cloud SQL for PostgreSQL 17: the target database `app` and dbgateway's
# management database `dbgateway` (tokens, sessions, approvals, audit log).
# In production these belong on separate instances (docs/ha.md).

# Instance names cannot be reused for a while after deletion.
resource "random_id" "suffix" {
  byte_length = 3
}

resource "random_password" "admin" {
  length  = 32
  special = false
}

resource "random_password" "store" {
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
    tier              = "db-f1-micro"
    availability_type = "ZONAL"
    disk_size         = 10
    disk_type         = "PD_SSD"

    user_labels = local.labels

    backup_configuration {
      enabled = false
    }

    ip_configuration {
      # Cloud Run reaches the instance on its private IP; the public IP is
      # only for setup.sh from `allowed_cidr`.
      private_network = google_compute_network.this.id
      ipv4_enabled    = true

      # TLS is mandatory, without client certificates (dbgateway connects
      # directly, not through the Cloud SQL Auth Proxy).
      ssl_mode = "ENCRYPTED_ONLY"
      # Per-instance CA: its server certificate has no IP SAN, so clients use
      # sslmode=verify-ca, which with a CA unique to the instance also
      # verifies the server's identity.
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

  depends_on = [google_service_networking_connection.psa]
}

# Databases and users are deleted together with the instance: dropping them
# first fails because of the objects and grants that setup.sh creates.

resource "google_sql_database" "app" {
  name            = "app"
  instance        = google_sql_database_instance.this.name
  deletion_policy = "ABANDON"
}

resource "google_sql_database" "dbgateway" {
  name            = "dbgateway"
  instance        = google_sql_database_instance.this.name
  deletion_policy = "ABANDON"
}

# Built-in administrator, used only by setup.sh.
resource "google_sql_user" "admin" {
  name            = "dbgw_admin"
  instance        = google_sql_database_instance.this.name
  password        = random_password.admin.result
  deletion_policy = "ABANDON"
}

# Owner of the management database (setup.sh makes it own `dbgateway`);
# dbgateway creates its tables on start-up.
resource "google_sql_user" "store" {
  name            = "dbgw_store"
  instance        = google_sql_database_instance.this.name
  password        = random_password.store.result
  deletion_policy = "ABANDON"
}

# The Cloud Run service account as an IAM database user (auth: gcp_iam). It
# is both read_user and write_user: a Cloud Run service has one identity.
resource "google_sql_user" "iam" {
  name            = local.iam_db_user
  instance        = google_sql_database_instance.this.name
  type            = "CLOUD_IAM_SERVICE_ACCOUNT"
  deletion_policy = "ABANDON"
}

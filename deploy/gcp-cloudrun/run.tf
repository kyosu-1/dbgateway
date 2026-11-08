# The Cloud Run service running `dbgw serve`, its identity and secrets.

resource "google_service_account" "run" {
  account_id   = "${var.name}-run"
  display_name = "dbgateway on Cloud Run (${var.name})"
}

# roles/cloudsql.instanceUser: IAM database login (cloudsql.instances.login).
# roles/cloudsql.client: not needed for dbgateway's direct TLS connection,
# but lets the service account read instance metadata and use the Cloud SQL
# Auth Proxy / connectors when debugging. Both are project-wide; the project
# is assumed to be a disposable test project.
resource "google_project_iam_member" "run" {
  for_each = toset(["roles/cloudsql.instanceUser", "roles/cloudsql.client"])
  project  = var.project
  role     = each.value
  member   = google_service_account.run.member
}

# Management database DSN over the private IP. The CA is added by dbgateway
# from DBGW_DB_CA (store.sslrootcert_env).
resource "google_secret_manager_secret" "store_dsn" {
  secret_id = "${var.name}-store-dsn"

  replication {
    auto {}
  }

  depends_on = [google_project_service.this]
}

resource "google_secret_manager_secret_version" "store_dsn" {
  secret      = google_secret_manager_secret.store_dsn.id
  secret_data = "postgres://${google_sql_user.store.name}:${random_password.store.result}@${google_sql_database_instance.this.private_ip_address}:5432/${google_sql_database.dbgateway.name}?sslmode=verify-ca"
}

# The service account may read this secret only.
resource "google_secret_manager_secret_iam_member" "store_dsn" {
  secret_id = google_secret_manager_secret.store_dsn.id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.run.member
}

# Created only once an image has been pushed (var.image), so that the first
# apply can create the Artifact Registry repository for deploy.sh.
resource "google_cloud_run_v2_service" "this" {
  count = var.image == "" ? 0 : 1

  name                 = var.name
  location             = var.region
  deletion_protection  = false
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = false # every request needs roles/run.invoker

  template {
    service_account = google_service_account.run.email
    # MCP over Streamable HTTP may hold a response stream open; allow up to
    # the maximum request timeout.
    timeout = "3600s"

    # One instance always runs: dbgateway's background loops (executing
    # approved requests, expiring approvals, tokens and sessions, audit
    # retention) must keep running between requests. Two at most to exercise
    # the multi-instance code paths (shared PostgreSQL store, conditional
    # updates for exactly-once execution).
    scaling {
      min_instance_count = 1
      max_instance_count = 2
    }

    vpc_access {
      network_interfaces {
        network    = google_compute_network.this.id
        subnetwork = google_compute_subnetwork.run.id
      }
      # Only RFC 1918 destinations (Cloud SQL's private IP) go through the
      # VPC; Google APIs and the metadata server are reached directly.
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = var.image
      # Cloud Run's `command` replaces the image ENTRYPOINT and `args`
      # replaces CMD. The image's ENTRYPOINT is /usr/local/bin/dbgw and its
      # CMD is `serve --config /etc/dbgateway/dbgateway.yaml`; with only
      # `serve`, dbgw reads the configuration from DBGW_CONFIG_YAML.
      args = ["serve"]

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        # CPU always allocated ("instance-based billing"). With the default
        # (cpu_idle = true) CPU is throttled to almost zero outside requests,
        # which would stall the approval executor and expiry loops above.
        cpu_idle          = false
        startup_cpu_boost = true
      }

      env {
        name  = "DBGW_CONFIG_YAML"
        value = local.dbgateway_config
      }
      env {
        name  = "DBGW_DB_CA"
        value = google_sql_database_instance.this.server_ca_cert[0].cert
      }
      env {
        name = "DBGW_STORE_DSN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.store_dsn.secret_id
            version = google_secret_manager_secret_version.store_dsn.version
          }
        }
      }

      startup_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        period_seconds    = 3
        timeout_seconds   = 2
        failure_threshold = 20
      }

      liveness_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        period_seconds    = 30
        timeout_seconds   = 5
        failure_threshold = 3
      }
    }
  }

  depends_on = [
    google_project_service.this,
    google_project_iam_member.run,
    google_secret_manager_secret_iam_member.store_dsn,
    google_sql_user.iam,
  ]
}

# Only the tester may invoke the service (no allUsers).
resource "google_cloud_run_v2_service_iam_member" "invoker" {
  count = length(google_cloud_run_v2_service.this)

  name     = google_cloud_run_v2_service.this[0].name
  location = google_cloud_run_v2_service.this[0].location
  role     = "roles/run.invoker"
  member   = var.invoker
}

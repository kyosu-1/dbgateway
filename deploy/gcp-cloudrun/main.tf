# A disposable Google Cloud environment that runs dbgateway itself on Cloud
# Run, in front of a Cloud SQL for PostgreSQL 17 instance reached over a
# private IP (Direct VPC egress + Private Service Access), with Cloud SQL
# IAM database authentication (auth: gcp_iam) as the Cloud Run service
# account and the management database / audit log in PostgreSQL.
#
# Not a production deployment: small tiers, no backups, no deletion
# protection, the target and the management database share one instance,
# and the Cloud SQL public IP is open to `allowed_cidr` for setup.sh. See
# README.md in this directory.

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

  default_labels = local.labels
}

data "google_project" "this" {
  project_id = var.project
}

locals {
  labels = {
    project    = "dbgateway"
    purpose    = "test"
    managed-by = "terraform"
  }

  # Cloud Run's deterministic URL (https://SERVICE-PROJECT_NUMBER.REGION.run.app).
  # dbgateway needs its public URL in the configuration (OAuth issuer,
  # redirect URIs, WebAuthn origin) before the service exists, so it cannot
  # use the service's `uri` attribute, which is the non-deterministic
  # https://SERVICE-<hash>.a.run.app form. Both URLs reach the same service.
  public_url = "https://${var.name}-${data.google_project.this.number}.${var.region}.run.app"

  # A service account's Cloud SQL IAM database user name is its email
  # without the ".gserviceaccount.com" suffix.
  iam_db_user = trimsuffix(google_service_account.run.email, ".gserviceaccount.com")

  # The rendered dbgateway configuration. It holds no secrets: the store DSN
  # and the database CA are passed as environment variables.
  dbgateway_config = templatefile("${path.module}/templates/dbgateway.yaml.tftpl", {
    public_url = local.public_url
    db_host    = google_sql_database_instance.this.private_ip_address
    db_user    = local.iam_db_user
    requester  = var.requester_email
    approver   = var.approver_email
  })

  artifact_repository = "${var.region}-docker.pkg.dev/${var.project}/${google_artifact_registry_repository.this.repository_id}"
}

resource "google_project_service" "this" {
  for_each = toset([
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "servicenetworking.googleapis.com",
    "compute.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# Artifact Registry repository for the dbgateway image (pushed by deploy.sh).
resource "google_artifact_registry_repository" "this" {
  repository_id = var.name
  location      = var.region
  format        = "DOCKER"
  description   = "dbgateway test images"

  depends_on = [google_project_service.this]
}

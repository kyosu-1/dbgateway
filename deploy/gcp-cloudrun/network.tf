# A dedicated VPC network: one subnet for Cloud Run Direct VPC egress and a
# Private Service Access range for Cloud SQL's private IP.

resource "google_compute_network" "this" {
  name                    = var.name
  auto_create_subnetworks = false

  depends_on = [google_project_service.this]
}

# Cloud Run instances take their egress IPs from this subnet (Direct VPC
# egress needs at least a /26; a /24 leaves room for revisions to overlap
# during deployments).
resource "google_compute_subnetwork" "run" {
  name                     = "${var.name}-run"
  network                  = google_compute_network.this.id
  region                   = var.region
  ip_cidr_range            = "10.43.0.0/24"
  private_ip_google_access = true
}

# Private Service Access: the range Cloud SQL allocates private IPs from.
# An explicit RFC 1918 range keeps it inside what Cloud Run routes through
# the VPC with egress = PRIVATE_RANGES_ONLY.
resource "google_compute_global_address" "psa" {
  name          = "${var.name}-psa"
  network       = google_compute_network.this.id
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  address       = "10.44.0.0"
  prefix_length = 20
}

resource "google_service_networking_connection" "psa" {
  network                 = google_compute_network.this.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.psa.name]

  # Deleting the peering right after the Cloud SQL instance usually fails
  # ("Producer services ... are still using this connection") because the
  # producer side is cleaned up asynchronously. ABANDON only drops it from
  # the state; the peering goes away with the network. See README.md if the
  # network itself cannot be deleted yet.
  deletion_policy = "ABANDON"
}

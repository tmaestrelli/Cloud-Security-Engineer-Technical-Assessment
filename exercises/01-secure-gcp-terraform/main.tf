locals {
  labels = {
    app        = var.name_prefix
    managed_by = "terraform"
  }

  # Required source ranges for Google Front Ends / health check probes
  # used by global external Application Load Balancers.
  lb_health_check_source_ranges = [
    "130.211.0.0/22",
    "35.191.0.0/16"
  ]

  startup_script = <<-EOT
    #!/bin/bash
    set -euo pipefail

    apt-get update
    apt-get install -y nginx

    cat > /var/www/html/index.html <<'EOF'
    <!doctype html>
    <html>
      <head>
        <title>Secure GCP Assessment</title>
      </head>
      <body>
        <h1>Secure backend served through HTTPS Load Balancer</h1>
        <p>This VM has no public IP and only accepts HTTP from the Google Load Balancer ranges.</p>
      </body>
    </html>
    EOF

    systemctl enable nginx
    systemctl restart nginx
  EOT
}

# -----------------------------
# Network
# -----------------------------

resource "google_compute_network" "main" {
  project                 = var.project_id
  name                    = "${var.name_prefix}-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
}

resource "google_compute_subnetwork" "public" {
  project                  = var.project_id
  name                     = "${var.name_prefix}-public-${var.region}"
  region                   = var.region
  network                  = google_compute_network.main.id
  ip_cidr_range            = var.public_subnet_cidr
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "private" {
  project                  = var.project_id
  name                     = "${var.name_prefix}-private-${var.region}"
  region                   = var.region
  network                  = google_compute_network.main.id
  ip_cidr_range            = var.private_subnet_cidr
  private_ip_google_access = true
}

# Optional NAT for outbound internet access from private VM.
# This lets the VM install packages without receiving a public IP.
resource "google_compute_router" "nat_router" {
  count   = var.enable_cloud_nat ? 1 : 0
  project = var.project_id
  name    = "${var.name_prefix}-nat-router"
  region  = var.region
  network = google_compute_network.main.id
}

resource "google_compute_router_nat" "nat" {
  count                              = var.enable_cloud_nat ? 1 : 0
  project                            = var.project_id
  name                               = "${var.name_prefix}-cloud-nat"
  router                             = google_compute_router.nat_router[0].name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.private.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# -----------------------------
# IAM / Service Account
# -----------------------------

resource "google_service_account" "vm" {
  project      = var.project_id
  account_id   = "${var.name_prefix}-vm-sa"
  display_name = "Least privilege service account for ${var.name_prefix} backend VM"
}

# Optional minimal operational roles.
# No roles/editor or roles/owner are used.
resource "google_project_iam_member" "vm_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.vm.email}"
}

resource "google_project_iam_member" "vm_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.vm.email}"
}

# Optional human admin access for IAP + OS Login.
resource "google_project_iam_member" "iap_tunnel_user" {
  for_each = toset(var.ssh_admin_members)

  project = var.project_id
  role    = "roles/iap.tunnelResourceAccessor"
  member  = each.value
}

resource "google_project_iam_member" "os_login_user" {
  for_each = toset(var.ssh_admin_members)

  project = var.project_id
  role    = "roles/compute.osLogin"
  member  = each.value
}

# -----------------------------
# Compute Engine backend VM
# -----------------------------

resource "google_compute_instance" "app" {
  project      = var.project_id
  name         = "${var.name_prefix}-app-vm"
  machine_type = var.machine_type
  zone         = var.zone
  labels       = local.labels

  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = 20
      type  = "pd-balanced"
    }
  }

  # No access_config block means no external public IP.
  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }

  metadata = {
    block-project-ssh-keys = "true"
    enable-oslogin         = "TRUE"
    serial-port-enable     = "FALSE"
  }

  metadata_startup_script = local.startup_script

  service_account {
    email = google_service_account.vm.email

    # Narrow scopes for basic logging/monitoring instead of full cloud-platform.
    scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write"
    ]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}

resource "google_compute_instance_group" "app" {
  project = var.project_id
  name    = "${var.name_prefix}-app-uig"
  zone    = var.zone

  instances = [
    google_compute_instance.app.self_link
  ]

  named_port {
    name = "http"
    port = 80
  }
}

# -----------------------------
# Firewall rules
# -----------------------------

resource "google_compute_firewall" "allow_ssh_from_trusted_ranges" {
  project     = var.project_id
  name        = "${var.name_prefix}-allow-ssh-trusted"
  network     = google_compute_network.main.name
  direction   = "INGRESS"
  priority    = 1000
  description = "Allow SSH only from trusted ranges to backend VM service account."

  source_ranges = var.trusted_ssh_source_ranges

  target_service_accounts = [
    google_service_account.vm.email
  ]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_http_from_lb_to_backend" {
  project     = var.project_id
  name        = "${var.name_prefix}-allow-http-from-lb"
  network     = google_compute_network.main.name
  direction   = "INGRESS"
  priority    = 1000
  description = "Allow HTTP only from Google Load Balancer / health check ranges to backend VM."

  source_ranges = local.lb_health_check_source_ranges

  target_service_accounts = [
    google_service_account.vm.email
  ]

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# -----------------------------
# Global external HTTPS Application Load Balancer
# -----------------------------

resource "google_compute_health_check" "http" {
  project = var.project_id
  name    = "${var.name_prefix}-http-health-check"

  timeout_sec         = 5
  check_interval_sec  = 10
  healthy_threshold   = 2
  unhealthy_threshold = 3

  http_health_check {
    port         = 80
    request_path = "/"
  }

  log_config {
    enable = true
  }
}

resource "google_compute_backend_service" "app" {
  project               = var.project_id
  name                  = "${var.name_prefix}-backend-service"
  protocol              = "HTTP"
  port_name             = "http"
  timeout_sec           = 30
  load_balancing_scheme = "EXTERNAL_MANAGED"

  health_checks = [
    google_compute_health_check.http.id
  ]

  backend {
    group           = google_compute_instance_group.app.self_link
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "app" {
  project         = var.project_id
  name            = "${var.name_prefix}-url-map"
  default_service = google_compute_backend_service.app.id
}

resource "google_compute_managed_ssl_certificate" "app" {
  project = var.project_id
  name    = "${var.name_prefix}-managed-cert"

  managed {
    domains = var.certificate_domains
  }
}

resource "google_compute_target_https_proxy" "app" {
  project          = var.project_id
  name             = "${var.name_prefix}-https-proxy"
  url_map          = google_compute_url_map.app.id
  ssl_certificates = [google_compute_managed_ssl_certificate.app.id]
}

resource "google_compute_global_address" "lb_ip" {
  project      = var.project_id
  name         = "${var.name_prefix}-lb-ip"
  address_type = "EXTERNAL"
  ip_version   = "IPV4"
}

resource "google_compute_global_forwarding_rule" "https" {
  project               = var.project_id
  name                  = "${var.name_prefix}-https-forwarding-rule"
  ip_address            = google_compute_global_address.lb_ip.address
  ip_protocol           = "TCP"
  port_range            = "443"
  target                = google_compute_target_https_proxy.app.id
  load_balancing_scheme = "EXTERNAL_MANAGED"
}
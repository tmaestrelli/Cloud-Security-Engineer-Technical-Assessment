variable "project_id" {
  description = "GCP project ID where resources will be deployed."
  type        = string
}

variable "name_prefix" {
  description = "Short prefix used for resource names. Keep it short because some GCP resources have name length limits."
  type        = string
  default     = "cse"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.name_prefix))
    error_message = "name_prefix must start with a lowercase letter, contain only lowercase letters, numbers, or hyphens, and be 3-21 characters long."
  }
}

variable "region" {
  description = "GCP region for regional resources."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone for the Compute Engine instance."
  type        = string
  default     = "us-central1-a"
}

variable "public_subnet_cidr" {
  description = "CIDR range for the public subnet. The global external load balancer is not actually placed in this subnet, but it is included to satisfy the assessment topology."
  type        = string
  default     = "10.10.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR range for the private subnet where the VM instance is deployed."
  type        = string
  default     = "10.10.2.0/24"
}

variable "trusted_ssh_source_ranges" {
  description = "Trusted CIDR ranges allowed to reach SSH on the private VM. Use a corporate VPN, bastion range, or IAP TCP forwarding range. Never use 0.0.0.0/0."
  type        = list(string)
  default     = ["35.235.240.0/20"]

  validation {
    condition = alltrue([
      for cidr in var.trusted_ssh_source_ranges :
      cidr != "0.0.0.0/0" && cidr != "::/0"
    ])
    error_message = "trusted_ssh_source_ranges must not include 0.0.0.0/0 or ::/0."
  }
}

variable "certificate_domains" {
  description = "Domains for the Google-managed SSL certificate. DNS must point to the load balancer IP for certificate provisioning."
  type        = list(string)

  validation {
    condition     = length(var.certificate_domains) > 0
    error_message = "At least one certificate domain is required for the HTTPS load balancer."
  }
}

variable "machine_type" {
  description = "Machine type for the backend VM."
  type        = string
  default     = "e2-micro"
}

variable "boot_image" {
  description = "Boot image for the backend VM."
  type        = string
  default     = "debian-cloud/debian-12"
}

variable "enable_cloud_nat" {
  description = "Whether to create Cloud NAT so the private VM can reach the internet for package updates without having a public IP."
  type        = bool
  default     = true
}

variable "ssh_admin_members" {
  description = "Optional IAM members allowed to use IAP TCP forwarding and OS Login. Example: user:name@example.com"
  type        = list(string)
  default     = []
}
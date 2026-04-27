provider "google" {
  project = var.project_id
  region  = var.region
}

module "secure_gcp_web" {
  source = "../"

  project_id = var.project_id
  region     = var.region
  zone       = var.zone

  name_prefix = var.name_prefix

  certificate_domains = var.certificate_domains

  trusted_ssh_source_ranges = var.trusted_ssh_source_ranges

  ssh_admin_members = var.ssh_admin_members
}

variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "name_prefix" {
  type    = string
  default = "cse"
}

variable "certificate_domains" {
  type = list(string)
}

variable "trusted_ssh_source_ranges" {
  type    = list(string)
  default = ["35.235.240.0/20"]
}

variable "ssh_admin_members" {
  type    = list(string)
  default = []
}
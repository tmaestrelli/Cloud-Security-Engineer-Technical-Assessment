output "vpc_name" {
  description = "Created VPC name."
  value       = google_compute_network.main.name
}

output "public_subnet_name" {
  description = "Created public subnet name."
  value       = google_compute_subnetwork.public.name
}

output "private_subnet_name" {
  description = "Created private subnet name."
  value       = google_compute_subnetwork.private.name
}

output "backend_instance_name" {
  description = "Private backend VM name."
  value       = google_compute_instance.app.name
}

output "backend_instance_internal_ip" {
  description = "Internal IP address of the backend VM."
  value       = google_compute_instance.app.network_interface[0].network_ip
}

output "load_balancer_ip" {
  description = "Public IPv4 address of the HTTPS load balancer."
  value       = google_compute_global_address.lb_ip.address
}

output "load_balancer_url" {
  description = "HTTPS URL for the first configured certificate domain."
  value       = "https://${var.certificate_domains[0]}"
}
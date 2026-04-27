# Secure GCP Web Infrastructure

This module deploys a secure GCP baseline with:

- A custom VPC.
- A public subnet and a private subnet.
- A private Compute Engine VM with no public IP.
- A global external HTTPS Application Load Balancer.
- Firewall rules allowing:
  - HTTPS only on the public load balancer frontend.
  - SSH only from trusted ranges.
  - HTTP only from Google Load Balancer / health check ranges to the backend VM.
- A dedicated least-privilege VM service account.

## Important GCP design note

In GCP, the global external HTTP(S) Load Balancer is not deployed inside a subnet in the same way an AWS ALB is deployed into public subnets.

The frontend is represented by a global forwarding rule and public IP address. The backend VM is deployed in the private subnet. The public subnet is included to satisfy the requested topology, but the global load balancer frontend itself is not bound to that subnet.

## Security decisions

### Private backend VM

The Compute Engine instance is deployed without an `access_config` block, meaning it receives no external IP address.

### HTTPS-only public exposure

Only a global forwarding rule on TCP/443 is created. No TCP/80 public forwarding rule is created.

### Backend HTTP restriction

The VM only accepts HTTP/80 from Google Load Balancer and health check source ranges:

- `130.211.0.0/22`
- `35.191.0.0/16`

### SSH restriction

SSH is restricted to `trusted_ssh_source_ranges`.

By default, the module uses the IAP TCP forwarding range:

- `35.235.240.0/20`

For a corporate environment, this could be replaced with a VPN, bastion, or corporate egress CIDR.

### IAM least privilege

The VM uses a dedicated service account instead of the default Compute Engine service account. It is granted only basic logging and monitoring writer permissions. No `roles/editor` or `roles/owner` permissions are used.

## Example usage

```hcl
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

module "secure_gcp_web" {
  source = "./terraform/modules/secure-gcp-web"

  project_id = "my-project-id"

  name_prefix = "cse"
  region      = "us-central1"
  zone        = "us-central1-a"

  certificate_domains = [
    "app.example.com"
  ]

  trusted_ssh_source_ranges = [
    "35.235.240.0/20"
  ]

  ssh_admin_members = [
    "user:admin@example.com"
  ]
}
```

## Validation Scope

This solution was validated with:

```bash
terraform init
terraform fmt -check -recursive
terraform validate
terraform plan -out=tfplan
```
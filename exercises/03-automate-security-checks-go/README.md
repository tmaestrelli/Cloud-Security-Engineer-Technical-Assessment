# Exercise 3 — Automate Security Checks with Go

## Objective

This exercise implements a Go CLI that scans cloud firewall rules across AWS, GCP, and Azure and reports inbound rules that expose traffic to `0.0.0.0/0`.

The output is JSON.

## Implementation Approach

Go is not my primary programming language, so I kept the implementation straightforward and focused on the cloud security logic rather than advanced Go patterns.

The security objective is to clearly identify inbound internet exposure across the three cloud providers:

- AWS: EC2 Security Groups with ingress rules containing `0.0.0.0/0`.
- GCP: firewall rules with direction `INGRESS` and `sourceRanges` containing `0.0.0.0/0`.
- Azure: NSG inbound allow rules where source is `0.0.0.0/0`, `*`, `Any`, or `Internet`.

The tool is read-only and does not attempt remediation.

## Files

| File | Purpose |
|---|---|
| `main.go` | Single-file Go CLI implementation |
| `go.mod` | Go module definition |

## Authentication

### AWS

The AWS scanner uses the AWS SDK for Go default credential chain.

Examples:

```bash
export AWS_PROFILE=my-profile
export AWS_REGION=us-east-1
```

### GCP

The GCP scanner uses Application Default Credentials.

Examples:

```bash
gcloud auth application-default login
```

### Azure

The Azure scanner uses Azure DefaultAzureCredential.

Examples:
```bash
az login
az account set --subscription "<subscription-id>"
```

## Usage

### Install dependencies:

```bash
go mod tidy
```
### Run all configured providers:

```bash
go run . \
  --aws-regions us-east-1,us-west-2 \
  --gcp-project my-gcp-project \
  --azure-subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### Run AWS only:

```bash
go run . --aws-regions us-east-1
```

### Run GCP only:

```bash
go run . --gcp-project my-gcp-project
```

### Run Azure only:

```bash
go run . --azure-subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Example Output
```bash
{
  "aws": {
    "security_groups": [
      {
        "id": "sg-12345678",
        "name": "open-sg",
        "region": "us-east-1",
        "insecure_rules": [
          {
            "protocol": "tcp",
            "port": "8080",
            "source": "0.0.0.0/0"
          }
        ]
      }
    ]
  },
  "gcp": {
    "firewall_rules": []
  },
  "azure": {
    "nsgs": []
  }
}```
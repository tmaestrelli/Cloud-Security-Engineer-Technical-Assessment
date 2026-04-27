# Exercise 4 — Automate Security Checks with Python

## Objective

This Python script lists storage buckets/containers across AWS, GCP, and Azure and generates a CSV report showing:

- Cloud provider
- Bucket/container name
- Public access status
- Encryption status

## Implementation Approach

This script is intentionally straightforward and security-focused.

It checks:

- AWS S3 buckets
- GCP Cloud Storage buckets
- Azure Blob Storage containers

The output file is a CSV report.

## Files

| File | Purpose |
|---|---|
| `main.py` | Python script that performs the storage security checks |
| `requirements.txt` | Python package dependencies |

## Authentication

### AWS

Uses Boto3's default credential chain.

Examples:

```bash
export AWS_PROFILE=my-profile
```

### GCP

Uses Google Application Default Credentials.

```bash
gcloud auth application-default login
```

### Azure

Uses Azure DefaultAzureCredential.

```bash
az login
az account set --subscription "<subscription-id>"
```

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run

All providers:

```bash
python main.py \
  --providers aws,gcp,azure \
  --gcp-project my-gcp-project \
  --azure-subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --output storage_security_report.csv
```

AWS only:

```bash
python main.py --providers aws --output storage_security_report.csv
```

GCP only:

```bash
python main.py \
  --providers gcp \
  --gcp-project my-gcp-project \
  --output storage_security_report.csv
```

Azure only:

```bash
python main.py \
  --providers azure \
  --azure-subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --output storage_security_report.csv
```

Example Output
```bash
cloud,bucket_name,public_access,encryption_enabled
AWS,my-public-bucket,Yes,No
GCP,logs-storage,No,Yes
Azure,mystorageaccount/shared-container,Yes,Yes
```

## Security Notes
### AWS

The script checks:

S3 Public Access Block configuration.
S3 bucket policy public status.
S3 default encryption configuration.

If a bucket does not have full Public Access Block enabled, the script reports public access as Yes from a conservative security posture. That does not always prove the bucket is currently publicly readable, but it indicates the bucket is not fully protected against public exposure.

### GCP

The script checks GCS IAM policy bindings for:

allUsers
allAuthenticatedUsers

If either member appears in the bucket IAM policy, the bucket is reported as public.

Cloud Storage encrypts data at rest by default, so encryption is reported as Yes when bucket metadata can be read.

### Azure

The script lists Storage Accounts and Blob containers through the Azure management API.

A container is reported public if:

The storage account allows blob public access; and
The container public access level is Blob or Container.

Azure Storage uses service-side encryption by default, so encryption is reported as Yes unless the management API explicitly reports otherwise.

### Scope and Limitations

This is an assessment-focused script, not a full CSPM product.

Known limitations:

It does not auto-enumerate multiple AWS accounts.
It does not auto-enumerate multiple GCP projects.
It does not auto-enumerate multiple Azure subscriptions.
It does not remediate findings.
GCP public access detection focuses on IAM policy bindings, as requested by the exercise.
The CSV uses Unknown if permissions are insufficient to determine a setting.
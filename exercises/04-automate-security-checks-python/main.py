import argparse
import csv
import sys
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError
from google.cloud import storage
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient


CSV_FIELDS = [
    "cloud",
    "bucket_name",
    "public_access",
    "encryption_enabled",
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a CSV report for storage bucket/container public access and encryption posture."
    )

    parser.add_argument(
        "--providers",
        default="aws,gcp,azure",
        help="Comma-separated providers to scan: aws,gcp,azure",
    )

    parser.add_argument(
        "--aws-profile",
        default=None,
        help="Optional AWS profile name. If not provided, boto3 uses its default credential chain.",
    )

    parser.add_argument(
        "--gcp-project",
        default=None,
        help="GCP project ID to scan.",
    )

    parser.add_argument(
        "--azure-subscription-id",
        default=None,
        help="Azure subscription ID to scan.",
    )

    parser.add_argument(
        "--output",
        default="storage_security_report.csv",
        help="CSV output file path.",
    )

    args = parser.parse_args()

    providers = parse_csv(args.providers)
    rows: List[Dict[str, str]] = []
    errors: List[str] = []

    if "aws" in providers:
        try:
            rows.extend(scan_aws_s3(args.aws_profile))
        except Exception as exc:
            errors.append(f"AWS scan failed: {exc}")

    if "gcp" in providers:
        if not args.gcp_project:
            errors.append("GCP scan skipped: --gcp-project is required.")
        else:
            try:
                rows.extend(scan_gcp_storage(args.gcp_project))
            except Exception as exc:
                errors.append(f"GCP scan failed: {exc}")

    if "azure" in providers:
        if not args.azure_subscription_id:
            errors.append("Azure scan skipped: --azure-subscription-id is required.")
        else:
            try:
                rows.extend(scan_azure_blob_storage(args.azure_subscription_id))
            except Exception as exc:
                errors.append(f"Azure scan failed: {exc}")

    write_csv(args.output, rows)

    print(f"CSV report written to: {args.output}")

    if errors:
        print("\nWarnings/errors:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)


def scan_aws_s3(profile_name: Optional[str]) -> List[Dict[str, str]]:
    session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
    s3 = session.client("s3")

    response = s3.list_buckets()
    rows: List[Dict[str, str]] = []

    for bucket in response.get("Buckets", []):
        bucket_name = bucket["Name"]

        rows.append(
            {
                "cloud": "AWS",
                "bucket_name": bucket_name,
                "public_access": aws_public_access_status(s3, bucket_name),
                "encryption_enabled": aws_encryption_status(s3, bucket_name),
            }
        )

    return rows


def aws_public_access_status(s3_client, bucket_name: str) -> str:
    """
    Security logic:
    - If AWS says the bucket policy is public, report Yes.
    - If all four S3 Public Access Block controls are enabled, report No.
    - If Public Access Block is missing or incomplete, report Yes as a weak/public-access-risk posture.

    This is intentionally conservative for a security assessment.
    """

    try:
        policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        if policy_status.get("PolicyStatus", {}).get("IsPublic") is True:
            return "Yes"
    except ClientError:
        pass

    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response.get("PublicAccessBlockConfiguration", {})

        required_controls = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]

        all_controls_enabled = all(config.get(control) is True for control in required_controls)

        return "No" if all_controls_enabled else "Yes"

    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")

        if error_code in [
            "NoSuchPublicAccessBlockConfiguration",
            "NoSuchPublicAccessBlock",
        ]:
            return "Yes"

        return "Unknown"


def aws_encryption_status(s3_client, bucket_name: str) -> str:
    """
    S3 now has default encryption behavior, but this call checks whether
    the bucket reports a default server-side encryption configuration.
    """

    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return "Yes"
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")

        if error_code in [
            "ServerSideEncryptionConfigurationNotFoundError",
            "NoSuchBucket",
        ]:
            return "No"

        return "Unknown"


def scan_gcp_storage(project_id: str) -> List[Dict[str, str]]:
    client = storage.Client(project=project_id)
    rows: List[Dict[str, str]] = []

    for bucket in client.list_buckets(project=project_id):
        bucket.reload()

        rows.append(
            {
                "cloud": "GCP",
                "bucket_name": bucket.name,
                "public_access": gcp_public_access_status(bucket),
                "encryption_enabled": gcp_encryption_status(bucket),
            }
        )

    return rows


def gcp_public_access_status(bucket) -> str:
    """
    Security logic:
    The exercise asks to check GCS public access through IAM policies.
    A bucket is reported public if its IAM policy grants access to:
    - allUsers
    - allAuthenticatedUsers
    """

    try:
        policy = bucket.get_iam_policy(requested_policy_version=3)

        for binding in policy.bindings:
            members = binding.get("members", [])

            if "allUsers" in members or "allAuthenticatedUsers" in members:
                return "Yes"

        return "No"

    except Exception:
        return "Unknown"


def gcp_encryption_status(bucket) -> str:
    """
    Cloud Storage encrypts objects at rest by default.

    The bucket.default_kms_key_name value can be used to identify whether
    a customer-managed key is configured, but a missing KMS key does not mean
    the bucket is unencrypted.
    """

    return "Yes"


def scan_azure_blob_storage(subscription_id: str) -> List[Dict[str, str]]:
    credential = DefaultAzureCredential()
    storage_client = StorageManagementClient(credential, subscription_id)

    rows: List[Dict[str, str]] = []

    for account in storage_client.storage_accounts.list():
        resource_group = extract_resource_group_from_id(account.id)

        if not resource_group:
            continue

        account_properties = storage_client.storage_accounts.get_properties(
            resource_group,
            account.name,
        )

        encryption_enabled = azure_blob_encryption_status(account_properties)
        account_allows_public_access = getattr(account_properties, "allow_blob_public_access", None)

        containers = storage_client.blob_containers.list(
            resource_group,
            account.name,
        )

        for container in containers:
            rows.append(
                {
                    "cloud": "Azure",
                    "bucket_name": f"{account.name}/{container.name}",
                    "public_access": azure_container_public_access_status(
                        container,
                        account_allows_public_access,
                    ),
                    "encryption_enabled": encryption_enabled,
                }
            )

    return rows


def azure_container_public_access_status(container, account_allows_public_access) -> str:
    """
    Security logic:
    Azure public blob access can be controlled at the storage account level
    and at the container level.

    If the account disables public blob access, the container is treated as not public.
    Otherwise, container-level public access values such as Blob or Container are public.
    """

    if account_allows_public_access is False:
        return "No"

    public_access = enum_to_string(getattr(container, "public_access", None)).lower()

    if public_access in ["blob", "container"]:
        return "Yes"

    return "No"


def azure_blob_encryption_status(account_properties) -> str:
    """
    Azure Storage encryption is enabled by default.

    This attempts to read the blob encryption service setting from the storage account.
    If the SDK object does not expose the nested field, return Yes because Azure Storage
    service-side encryption is platform-default behavior.
    """

    try:
        enabled = account_properties.encryption.services.blob.enabled
        return "Yes" if enabled else "No"
    except AttributeError:
        return "Yes"


def extract_resource_group_from_id(resource_id: str) -> Optional[str]:
    if not resource_id:
        return None

    parts = resource_id.split("/")

    for index, part in enumerate(parts):
        if part.lower() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1]

    return None


def enum_to_string(value) -> str:
    if value is None:
        return ""

    if hasattr(value, "value"):
        return str(value.value)

    return str(value)


def parse_csv(value: str) -> List[str]:
    return [
        item.strip().lower()
        for item in value.split(",")
        if item.strip()
    ]


def write_csv(path: str, rows: List[Dict[str, str]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for row in rows:
            writer.writerow(row)


if __name__ == "__main__":
    main()
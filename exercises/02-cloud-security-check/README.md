# Exercise 2 — Cloud Security Check

## Objective

This exercise reviews an insecure CloudFormation template and Dockerfile.

For the CloudFormation template, the corrected version is provided in `CloudFormation_template.yaml`. The file keeps the original insecure patterns as comments, explains why they are risky, and implements the corrected resources as active CloudFormation code.

For the Dockerfile, the exercise only asks to identify the issues. Those findings are documented directly inside `app.dockerfile` as inline review comments.

## Files

| File | Purpose |
|---|---|
| `CloudFormation_template.yaml` | Remediated CloudFormation template with comments explaining the original issues and applied best practices |
| `app.dockerfile` | Line-by-line Dockerfile security review with the original insecure patterns preserved as comments |

## Preventing Misconfigurations from Being Introduced or Applied

Misconfigurations should be prevented before they reach production. I would apply controls at three levels: developer workstation, CI/CD pipeline, and cloud/runtime governance.

### CloudFormation Prevention

For CloudFormation templates, I would use:

- `cfn-lint` to validate CloudFormation syntax and resource structure.
- `cfn-nag`, Checkov, or similar IaC scanners to detect insecure patterns.
- IAM Access Analyzer policy validation to identify overly permissive IAM policies.
- CloudFormation Guard to enforce organization-specific policy-as-code rules.
- AWS Config and Security Hub to detect deployed resources that drift from the expected security posture.
- Service Control Policies to block dangerous actions in production accounts.

Examples of checks that should fail before deployment:

- IAM policy with `Action: "*"` and `Resource: "*"`.
- IAM permissions attached directly to users without justification.
- S3 bucket without public access blocking.
- S3 bucket without default encryption.
- S3 bucket without TLS-only access enforcement.
- CloudFormation template creating long-lived IAM users for workload access.

### Dockerfile and Container Prevention

For Dockerfiles and container images, I would use:

- Hadolint for Dockerfile best-practice checks.
- Trivy or Grype for container image vulnerability scanning.
- Gitleaks or GitHub secret scanning to prevent hardcoded secrets from being committed.
- Dependency scanning for application packages.
- `.dockerignore` to prevent sensitive or unnecessary files from entering the image build context.
- Admission controls or deployment policies to block unsafe images from running.

Examples of checks that should fail before deployment:

- Hardcoded secrets in `ENV`.
- Container running as root.
- `chmod 777` or world-writable application directories.
- Broad `COPY .` without `.dockerignore`.
- Outdated base images.
- Critical or high vulnerabilities in the final image.
- Installation of unnecessary tools in production images.

### Runtime and Cloud Governance

Preventive controls should be complemented by detective controls:

- Monitor CloudTrail for IAM policy changes, access key creation, and privilege escalation attempts.
- Periodically review IAM credential reports.
- Use IAM Access Analyzer to detect broad or external access.
- Use AWS Config to detect non-compliant IAM and S3 resources.
- Use Security Hub to centralize and prioritize findings.
- Alert on secrets detected in repositories, CI logs, container registries, or deployed images.

The objective is to shift security left without relying only on manual review. Developers should receive fast feedback in pull requests, while cloud-side guardrails prevent unsafe changes from being applied to sensitive environments.
# Exercise 5 — Third-Party Dependency Security Audit

## Objective

This exercise analyzes a vulnerable Node.js `package.json`, scans third-party dependencies for known vulnerabilities, documents high and critical findings, explains how to remediate them, and provides security recommendations.

The exercise also includes a bonus Python script that parses `npm audit` JSON output and generates a CSV report containing high and critical vulnerabilities.

## Files

| File | Purpose |
|---|---|
| `package.json` | Vulnerable Node.js dependency manifest provided by the assessment |
| `package-lock.json` | Lockfile generated so `npm audit` can resolve the full dependency tree |
| `audit_to_csv.py` | Python script that runs or parses `npm audit --json` and generates a CSV report |
| `reports/npm-audit.json` | Raw `npm audit --json` output |
| `reports/npm-audit-high-critical.csv` | CSV report with high and critical findings |

## Tool Used

This exercise uses `npm audit`.

`npm audit` analyzes the dependency tree and reports known vulnerabilities affecting direct and transitive dependencies. The Python script processes the JSON output and extracts high and critical findings into a CSV report.

## How to Run

From this folder:

    exercises/05-third-party-dependency-audit

Install dependency metadata and generate the lockfile:

    npm install --package-lock-only --ignore-scripts

On Windows PowerShell, if `npm` is blocked by execution policy, use:

    npm.cmd install --package-lock-only --ignore-scripts

Run `npm audit` manually and save the JSON report:

    npm audit --json > reports/npm-audit.json

On Windows PowerShell, use:

    npm.cmd audit --json | Set-Content -Encoding utf8 reports/npm-audit.json

Then generate the CSV report:

    python audit_to_csv.py --input reports/npm-audit.json --output reports/npm-audit-high-critical.csv

Alternatively, the Python script can run `npm audit --json` directly:

    python audit_to_csv.py

The script is Windows-aware and uses `npm.cmd` automatically when running on Windows.

## Audit Summary

The generated audit report identified:

| Metric | Count |
|---|---:|
| High/Critical findings | 45 |
| Critical findings | 16 |
| High findings | 29 |
| Fixable according to `npm audit` | 45 |

The full high/critical report is available at:

    reports/npm-audit-high-critical.csv

## Output

The generated CSV contains:

| Column | Description |
|---|---|
| `package` | Package reported by npm audit |
| `vulnerable_dependency` | Direct or transitive dependency associated with the vulnerability |
| `severity` | Vulnerability severity |
| `title` | Vulnerability title |
| `vulnerable_range` | Affected version range |
| `is_direct` | Whether the package is a direct dependency |
| `fix_available` | Whether npm reports that a fix is available |
| `url` | Advisory URL when available |

Example output format:

    package,vulnerable_dependency,severity,title,vulnerable_range,is_direct,fix_available,url
    lodash,lodash,high,Prototype Pollution,<4.17.12,true,Yes,https://...

## Detected High/Critical Vulnerabilities

The provided `package.json` intentionally uses outdated dependencies that produce multiple high and critical findings.

Important vulnerable or risk-contributing dependencies include:

| Dependency | Current Version | Risk | Recommended Remediation |
|---|---:|---|---|
| `lodash` | `4.17.10` | Older lodash versions are associated with prototype pollution and related vulnerabilities | Upgrade to `lodash@4.17.21` or later |
| `express` | `4.15.0` | Outdated Express version with vulnerable direct/transitive dependency chain | Upgrade to the latest stable Express release and test compatibility |
| `body-parser` | `^1.19.0` | Older body-parser versions may include denial-of-service/resource consumption vulnerabilities | Upgrade to a current patched version |
| `jsonwebtoken` | `8.1.0` | Older JWT libraries have had signing/verification-related vulnerabilities | Upgrade to `jsonwebtoken@9.x` or later and validate JWT signing/verification behavior |
| `mongoose` | `^4.2.4` | Very old Mongoose version with vulnerable transitive dependencies and unsupported dependency chain | Upgrade to a supported Mongoose major version after compatibility testing |
| `mocha` | `5.0.5` | Old dev dependency that may introduce vulnerable transitive packages | Upgrade to the latest stable Mocha version |

## How to Fix the Issues

The remediation approach depends on whether the vulnerable package is a direct dependency, a transitive dependency, or part of an outdated dependency chain.

### 1. Fix direct vulnerable dependencies by upgrading them

Several vulnerable packages are direct dependencies in `package.json`. These should be upgraded explicitly.

Recommended upgrade direction:

    npm install lodash@latest
    npm install express@latest
    npm install body-parser@latest
    npm install jsonwebtoken@latest
    npm install mongoose@latest
    npm install --save-dev mocha@latest

On Windows PowerShell, use `npm.cmd` if `npm` is blocked by execution policy:

    npm.cmd install lodash@latest
    npm.cmd install express@latest
    npm.cmd install body-parser@latest
    npm.cmd install jsonwebtoken@latest
    npm.cmd install mongoose@latest
    npm.cmd install --save-dev mocha@latest

### 2. Fix transitive vulnerabilities by upgrading parent packages

Some vulnerabilities are introduced by transitive dependencies, meaning the vulnerable package is not listed directly in `package.json`.

In those cases, the preferred fix is usually to upgrade the parent dependency that pulls the vulnerable package.

Examples:

    npm install express@latest
    npm install mongoose@latest
    npm install --save-dev mocha@latest

After upgrading parent packages, regenerate the lockfile and rerun the audit.

### 3. Use `npm audit fix` for safe automatic fixes

First try non-breaking automatic fixes:

    npm audit fix

On Windows PowerShell:

    npm.cmd audit fix

Then rerun:

    npm audit

and regenerate the CSV report:

    python audit_to_csv.py

### 4. Use `npm audit fix --force` only after review

Some fixes require major version upgrades. These may introduce breaking changes.

Use this only after reviewing release notes and running tests:

    npm audit fix --force

On Windows PowerShell:

    npm.cmd audit fix --force

This is especially relevant for old packages such as `mongoose@4.x`, `jsonwebtoken@8.x`, and `mocha@5.x`, where remediation may require a major version upgrade.

### 5. Replace dependencies when upgrading is not enough

If a vulnerable package has no patched version, is no longer maintained, or cannot be upgraded safely, the correct remediation may be replacement.

Examples of replacement decisions:

| Situation | Fix |
|---|---|
| Package has no patched version | Replace the dependency |
| Package is abandoned or no longer maintained | Replace with a supported alternative |
| Upgrade requires large application changes | Plan a controlled migration |
| Dependency is unused | Remove it from `package.json` |
| Transitive dependency remains vulnerable after parent upgrade | Replace or remove the parent package |

Example commands:

    npm uninstall vulnerable-package
    npm install safer-maintained-alternative

### 6. Remove unused dependencies

If any vulnerable dependency is not actually required by the application, the best fix is removal.

Example:

    npm uninstall unused-package

This reduces both vulnerability exposure and dependency maintenance burden.

### 7. Validate after remediation

After upgrading, replacing, or removing dependencies:

    npm test
    npm audit
    python audit_to_csv.py

The target state should be:

- No critical vulnerabilities.
- No high vulnerabilities unless formally accepted as risk.
- Updated `package.json`.
- Updated `package-lock.json`.
- Application tests passing.

## How Many Issues Can Be Fixed?

The generated report identified 45 high/critical findings.

According to the `fixAvailable` field from `npm audit --json`, all 45 high/critical findings were reported as fixable.

Summary:

| Metric | Count |
|---|---:|
| High/Critical findings | 45 |
| Fixable findings | 45 |
| Not reported as fixable | 0 |

The Python script calculates this from the `fixAvailable` field and prints:

    Fixable according to npm audit: 45

The generated CSV also contains a `fix_available` column. Rows where `fix_available` starts with `Yes` are issues that npm reports as having an available fix.

## Recommended Remediation Order

I would remediate in this order:

1. Run `npm audit fix` to apply safe non-breaking fixes.
2. Rerun `npm audit` and regenerate the CSV report.
3. Review remaining high and critical findings.
4. Upgrade vulnerable direct dependencies manually.
5. Upgrade parent packages responsible for vulnerable transitive dependencies.
6. Replace abandoned or unfixable dependencies.
7. Use `npm audit fix --force` only after reviewing breaking changes.
8. Run application tests.
9. Commit the updated `package.json` and `package-lock.json`.

## Security Recommendations

To prevent similar dependency risks:

| Control | Purpose |
|---|---|
| `npm audit --audit-level=high` in CI | Fail builds when high or critical vulnerabilities are introduced |
| Dependabot or Renovate | Automatically propose dependency updates |
| Lockfile review | Ensure transitive dependency changes are visible |
| Pin and update dependencies regularly | Reduce exposure to stale vulnerable packages |
| Avoid unsupported major versions | Old frameworks often accumulate unresolved transitive risk |
| Require tests before major upgrades | Prevent breaking changes from being deployed blindly |
| Track exceptions | Document owner, justification, compensating controls, and expiration date |

## CI/CD Recommendation

A simple CI process for this project would:

1. Install dependencies using the lockfile.
2. Run `npm audit --json`.
3. Parse the audit output.
4. Fail the build if high or critical vulnerabilities are present.
5. Allow exceptions only when documented and time-bound.

Example policy:

    npm audit --audit-level=high

## Bonus Script

The bonus Python script supports two modes.

Run `npm audit` automatically and generate reports:

    python audit_to_csv.py

Parse an existing audit file:

    python audit_to_csv.py --input reports/npm-audit.json --output reports/npm-audit-high-critical.csv

The script handles the fact that `npm audit` may return a non-zero exit code when vulnerabilities are found. That behavior is expected and does not mean the script failed.

The script also handles Windows environments by using `npm.cmd` when needed.

## Validation

Validate the Python script syntax:

    python -m py_compile audit_to_csv.py

Expected generated files:

    reports/npm-audit.json
    reports/npm-audit-high-critical.csv

## Notes

This exercise focuses on security analysis and reporting. The vulnerable dependencies are intentionally kept in `package.json` so the audit can reproduce findings.

In a real project, the remediation would be applied, tested, and committed together with the updated `package-lock.json`.
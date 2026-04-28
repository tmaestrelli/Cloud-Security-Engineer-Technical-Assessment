import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


HIGH_PRIORITY = {"high", "critical"}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run npm audit and generate a high/critical vulnerability CSV report."
    )

    parser.add_argument(
        "--input",
        help="Optional existing npm audit JSON file. If omitted, the script runs npm audit --json.",
    )

    parser.add_argument(
        "--output",
        default="reports/npm-audit-high-critical.csv",
        help="Output CSV file path.",
    )

    parser.add_argument(
        "--json-output",
        default="reports/npm-audit.json",
        help="Path to save raw npm audit JSON when running npm audit.",
    )

    args = parser.parse_args()

    if args.input:
        audit_data = load_json(Path(args.input))
    else:
        audit_data = run_npm_audit(Path(args.json_output))

    findings = parse_npm_audit(audit_data)
    high_priority_findings = [
        finding for finding in findings
        if finding["severity"].lower() in HIGH_PRIORITY
    ]

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    write_csv(output_path, high_priority_findings)
    print_summary(high_priority_findings, output_path)


def run_npm_audit(json_output_path: Path) -> Dict[str, Any]:
    """
    npm audit returns a non-zero exit code when vulnerabilities are found.
    That is expected, so this function does not fail only because returncode != 0.
    """

    npm_command = "npm.cmd" if sys.platform.startswith("win") else "npm"

    result = subprocess.run(
        [npm_command, "audit", "--json"],
        capture_output=True,
        text=True,
    )

    if not result.stdout.strip():
        print(result.stderr, file=sys.stderr)
        raise RuntimeError("npm audit did not return JSON output.")

    json_output_path.parent.mkdir(parents=True, exist_ok=True)
    json_output_path.write_text(result.stdout, encoding="utf-8")

    return json.loads(result.stdout.lstrip("\ufeff"))


def parse_npm_audit(audit_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Supports the modern npm audit JSON format with a top-level 'vulnerabilities'
    object. Also includes basic support for older npm formats using 'advisories'.
    """

    if "vulnerabilities" in audit_data:
        return parse_modern_audit_format(audit_data)

    if "advisories" in audit_data:
        return parse_legacy_audit_format(audit_data)

    return []


def parse_modern_audit_format(audit_data: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []

    vulnerabilities = audit_data.get("vulnerabilities", {})

    for package_name, vulnerability in vulnerabilities.items():
        severity = str(vulnerability.get("severity", "unknown"))
        is_direct = str(vulnerability.get("isDirect", False))
        vulnerable_range = str(vulnerability.get("range", "unknown"))
        fix_available = normalize_fix_available(vulnerability.get("fixAvailable"))

        via_entries = vulnerability.get("via", [])

        if not via_entries:
            findings.append(
                build_finding(
                    package_name=package_name,
                    vulnerable_dependency=package_name,
                    severity=severity,
                    title="Unknown vulnerability",
                    vulnerable_range=vulnerable_range,
                    is_direct=is_direct,
                    fix_available=fix_available,
                    url="",
                )
            )
            continue

        for via in via_entries:
            if isinstance(via, str):
                findings.append(
                    build_finding(
                        package_name=package_name,
                        vulnerable_dependency=via,
                        severity=severity,
                        title=f"Transitive vulnerability via {via}",
                        vulnerable_range=vulnerable_range,
                        is_direct=is_direct,
                        fix_available=fix_available,
                        url="",
                    )
                )
                continue

            findings.append(
                build_finding(
                    package_name=package_name,
                    vulnerable_dependency=str(via.get("dependency", package_name)),
                    severity=str(via.get("severity", severity)),
                    title=str(via.get("title", "Unknown vulnerability")),
                    vulnerable_range=str(via.get("range", vulnerable_range)),
                    is_direct=is_direct,
                    fix_available=fix_available,
                    url=str(via.get("url", "")),
                )
            )

    return findings


def parse_legacy_audit_format(audit_data: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []

    advisories = audit_data.get("advisories", {})

    for _, advisory in advisories.items():
        findings.append(
            build_finding(
                package_name=str(advisory.get("module_name", "unknown")),
                vulnerable_dependency=str(advisory.get("module_name", "unknown")),
                severity=str(advisory.get("severity", "unknown")),
                title=str(advisory.get("title", "Unknown vulnerability")),
                vulnerable_range=str(advisory.get("vulnerable_versions", "unknown")),
                is_direct="unknown",
                fix_available=str(advisory.get("patched_versions", "unknown")),
                url=str(advisory.get("url", "")),
            )
        )

    return findings


def build_finding(
    package_name: str,
    vulnerable_dependency: str,
    severity: str,
    title: str,
    vulnerable_range: str,
    is_direct: str,
    fix_available: str,
    url: str,
) -> Dict[str, str]:
    return {
        "package": package_name,
        "vulnerable_dependency": vulnerable_dependency,
        "severity": severity,
        "title": title,
        "vulnerable_range": vulnerable_range,
        "is_direct": is_direct,
        "fix_available": fix_available,
        "url": url,
    }


def normalize_fix_available(value: Any) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, dict):
        package_name = value.get("name", "")
        version = value.get("version", "")
        is_semver_major = value.get("isSemVerMajor", False)

        result = f"Yes: {package_name}@{version}".strip()

        if is_semver_major:
            result += " (semver-major)"

        return result

    return str(value)


def write_csv(path: Path, findings: List[Dict[str, str]]) -> None:
    fieldnames = [
        "package",
        "vulnerable_dependency",
        "severity",
        "title",
        "vulnerable_range",
        "is_direct",
        "fix_available",
        "url",
    ]

    with path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for finding in findings:
            writer.writerow(finding)


def print_summary(findings: List[Dict[str, str]], output_path: Path) -> None:
    total = len(findings)
    fixable = sum(1 for finding in findings if finding["fix_available"].startswith("Yes"))

    critical = sum(1 for finding in findings if finding["severity"].lower() == "critical")
    high = sum(1 for finding in findings if finding["severity"].lower() == "high")

    print(f"Report written to: {output_path}")
    print(f"High/Critical findings: {total}")
    print(f"Critical: {critical}")
    print(f"High: {high}")
    print(f"Fixable according to npm audit: {fixable}")


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


if __name__ == "__main__":
    main()
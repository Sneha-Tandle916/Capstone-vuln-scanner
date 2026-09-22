import argparse
import json
import sys
import yaml


SEVERITY_ORDER = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "UNKNOWN",
]


def load_result(path):
    """Load and validate the Trivy JSON scan result."""
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as error:
        print(f"Gate error: {error}")
        sys.exit(2)


def load_threshold(config_path="config.yaml"):
    """Load fail_on_severity from config.yaml."""
    try:
        with open(config_path, "r", encoding="utf-8") as file:
            config = yaml.safe_load(file) or {}

        threshold = str(
            config.get("fail_on_severity", "CRITICAL")
        ).upper()

        if threshold not in SEVERITY_ORDER:
            print(f"Gate error: Invalid severity threshold: {threshold}")
            sys.exit(2)

        return threshold

    except (FileNotFoundError, yaml.YAMLError, OSError) as error:
        print(f"Gate error: {error}")
        sys.exit(2)


def derive_blocked_severities(threshold):
    """Return all severity levels that should block the build."""
    cutoff = SEVERITY_ORDER.index(threshold)
    return set(SEVERITY_ORDER[:cutoff + 1])


def get_vulnerabilities(result):
    """Collect vulnerabilities from every Trivy Results section."""
    vulnerabilities = []

    for scan_result in result.get("Results", []) or []:
        vulnerabilities.extend(
            scan_result.get("Vulnerabilities", []) or []
        )

    return vulnerabilities


def format_vuln_table(failing):
    """Print a readable list of blocking vulnerabilities."""
    if not failing:
        return

    print()
    print("Blocking vulnerabilities:")

    for vulnerability in failing:
        vuln_id = vulnerability.get("VulnerabilityID", "N/A")
        severity = vulnerability.get("Severity", "UNKNOWN")
        package = vulnerability.get("PkgName", "N/A")
        installed = vulnerability.get("InstalledVersion", "N/A")
        fixed = vulnerability.get("FixedVersion", "N/A")

        print(
            f"- {vuln_id} | {severity} | "
            f"{package} | installed: {installed} | fixed: {fixed}"
        )


def check_gate(result_path, config_path="config.yaml"):
    """
    Check the scan result against fail_on_severity.

    Exit codes:
        0 = PASS
        1 = BLOCKED
        2 = GATE/CONFIGURATION ERROR
    """
    result = load_result(result_path)
    threshold = load_threshold(config_path)
    blocked = derive_blocked_severities(threshold)

    vulnerabilities = get_vulnerabilities(result)

    failing = [
        vulnerability
        for vulnerability in vulnerabilities
        if str(
            vulnerability.get("Severity", "UNKNOWN")
        ).upper() in blocked
    ]

    if failing:
        print(
            f"BUILD BLOCKED - {len(failing)} "
            f"{threshold}+ vulnerabilities found"
        )
        format_vuln_table(failing)
        return 1

    print(f"GATE PASSED   no {threshold}+ vulnerabilities")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Check Trivy scan results against a severity threshold"
    )

    parser.add_argument(
        "result_file",
        help="Path to the Trivy JSON result"
    )

    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config.yaml"
    )

    args = parser.parse_args()

    exit_code = check_gate(
        args.result_file,
        args.config
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()

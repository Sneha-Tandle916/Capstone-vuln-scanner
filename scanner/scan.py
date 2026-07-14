import argparse
import json
import yaml

from scanner.trivy_runner import scan_image
from scanner.cve_parser import extract_vulnerabilities


def load_config(path="config.yaml"):
    """
    Load configuration from config.yaml.
    """

    with open(path, "r") as file:
        config = yaml.safe_load(file)

    return config


def run_scan(image_name: str, severity: str = None):
    """
    Run a vulnerability scan on the given Docker image.
    Returns both the raw Trivy JSON and parsed vulnerabilities.
    """

    config = load_config()

    if severity is None:
        severity = config.get(
            "severity_threshold",
            "HIGH,CRITICAL"
        )

    scan_result = scan_image(
        image_name,
        severity=severity
    )

    vulnerabilities = extract_vulnerabilities(scan_result)

    return scan_result, vulnerabilities


def summarize_vulnerabilities(vulnerabilities: list):
    """
    Count vulnerabilities by severity.
    """

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    for vuln in vulnerabilities:

        severity = vuln.get("severity", "UNKNOWN")

        if severity in summary:
            summary[severity] += 1
        else:
            summary["UNKNOWN"] += 1

    return summary


def save_json_report(scan_result: dict, filename: str):
    """
    Save the raw Trivy JSON report.
    """

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(scan_result, file, indent=4)

    print(f"\nJSON report saved to: {filename}")


def main():
    """
    Command-line entry point.
    """

    parser = argparse.ArgumentParser(
        description="Docker Image Vulnerability Scanner"
    )

    parser.add_argument(
        "image",
        help="Docker image to scan"
    )

    parser.add_argument(
        "--severity",
        default=None,
        help="Severity levels (Example: HIGH,CRITICAL)"
    )

    parser.add_argument(
        "--output-json",
        help="Save raw Trivy JSON report"
    )

    args = parser.parse_args()

    scan_result, vulnerabilities = run_scan(
        args.image,
        severity=args.severity
    )

    summary = summarize_vulnerabilities(vulnerabilities)

    print("\n" + "=" * 60)
    print("VULNERABILITY SUMMARY")
    print("=" * 60)

    print(f"Total Vulnerabilities : {len(vulnerabilities)}")
    print()

    for severity, count in summary.items():
        print(f"{severity:10}: {count}")

    if args.output_json:
        save_json_report(
            scan_result,
            args.output_json
        )


if __name__ == "__main__":
    main()
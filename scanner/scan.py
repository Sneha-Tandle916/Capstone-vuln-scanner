
import argparse
import json
import logging
import time
from functools import wraps

import yaml

from scanner.trivy_runner import scan_image
from scanner.cve_parser import extract_vulnerabilities


logger = logging.getLogger(__name__)


def retry(max_attempts=3, delay=5):
    """Retry a function on failure, then re-raise the last exception."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    if attempt == max_attempts:
                        raise

                    logger.warning(
                        "Attempt %s failed: %s. Retrying in %s seconds...",
                        attempt,
                        exc,
                        delay,
                    )
                    time.sleep(delay)

        return wrapper

    return decorator


def load_config(path="config.yaml"):
    """Load configuration from config.yaml."""

    with open(path, "r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    return config or {}


def run_scan(image_name: str, severity: str = None):
    """
    Run a vulnerability scan on the given Docker image.

    Returns the raw Trivy JSON and parsed vulnerabilities.
    """

    config = load_config()

    if severity is None:
        severity = config.get(
            "severity_threshold",
            "HIGH,CRITICAL",
        )

    scan_result = scan_image(
        image_name,
        severity=severity,
    )

    vulnerabilities = extract_vulnerabilities(scan_result)

    return scan_result, vulnerabilities


@retry(max_attempts=3, delay=5)
def run_scan_with_retry(image_name, config, severity=None, quiet=False):
    """Run the scan with retries and the requested severity filter."""

    selected_severity = severity or config.get(
        "severity_threshold",
        "HIGH,CRITICAL",
    )

    if not quiet:
        logger.info(
            "Starting scan for %s with severity filter: %s",
            image_name,
            selected_severity,
        )

    return run_scan(
        image_name,
        severity=selected_severity,
    )


def summarize_vulnerabilities(vulnerabilities: list):
    """Count vulnerabilities by severity."""

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "UNKNOWN").upper()

        if severity in summary:
            summary[severity] += 1
        else:
            summary["UNKNOWN"] += 1

    return summary


def save_json_report(scan_result: dict, filename: str):
    """Save the raw Trivy JSON report."""

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(scan_result, file, indent=4)

    print(f"\nJSON report saved to: {filename}")


def main():
    """Command-line entry point."""

    parser = argparse.ArgumentParser(
        description="Docker Image Vulnerability Scanner"
    )

    parser.add_argument(
        "image",
        help="Docker image to scan",
    )

    parser.add_argument(
        "--severity",
        default=None,
        help="Severity levels, for example HIGH,CRITICAL",
    )

    parser.add_argument(
        "--output-json",
        help="Save raw Trivy JSON report",
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce scanner log output",
    )

    args = parser.parse_args()
    config = load_config()

    scan_result, vulnerabilities = run_scan_with_retry(
        args.image,
        config,
        severity=args.severity,
        quiet=args.quiet,
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
        save_json_report(scan_result, args.output_json)


if __name__ == "__main__":
    main()

import argparse
import json
import logging
import os

import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_scan_result(filename: str) -> dict:
    """
    Load the scan result JSON file.
    """

    with open(
        filename,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def get_vulnerabilities(scan_result: dict) -> list:
    """
    Extract vulnerabilities from the raw Trivy JSON.
    """

    vulnerabilities = []

    for result in scan_result.get("Results", []):

        for vuln in result.get("Vulnerabilities", []):

            vulnerabilities.append({
                "id": vuln.get(
                    "VulnerabilityID",
                    "N/A"
                ),
                "package": vuln.get(
                    "PkgName",
                    "Unknown"
                ),
                "installed_version": vuln.get(
                    "InstalledVersion",
                    "Unknown"
                ),
                "fixed_version": vuln.get(
                    "FixedVersion",
                    "Not Fixed"
                ),
                "severity": vuln.get(
                    "Severity",
                    "UNKNOWN"
                ).upper(),
                "title": vuln.get(
                    "Title",
                    "No Title"
                ),
            })

    return vulnerabilities


def summarize_vulnerabilities(
    vulnerabilities: list
) -> dict:
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

        severity = vuln.get(
            "severity",
            "UNKNOWN"
        ).upper()

        if severity in summary:
            summary[severity] += 1
        else:
            summary["UNKNOWN"] += 1

    return summary


def send_slack(
    scan_result: dict,
    vulnerabilities: list
) -> None:
    """
    Send a Slack Block Kit notification.
    """

    webhook_url = os.getenv(
        "SLACK_WEBHOOK_URL"
    )

    if not webhook_url:
        raise RuntimeError(
            "SLACK_WEBHOOK_URL is not set."
        )

    summary = summarize_vulnerabilities(
        vulnerabilities
    )

    image_name = scan_result.get(
        "ArtifactName",
        "Unknown image"
    )

    top_findings = [
        vuln
        for vuln in vulnerabilities
        if vuln["severity"] in (
            "CRITICAL",
            "HIGH"
        )
    ][:5]

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Container Security Scan"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Image:*\n{image_name}"
                },
                {
                    "type": "mrkdwn",
                    "text": (
                        f"*Total:*\n"
                        f"{len(vulnerabilities)}"
                    )
                },
                {
                    "type": "mrkdwn",
                    "text": (
                        f"*Critical:*\n"
                        f"{summary['CRITICAL']}"
                    )
                },
                {
                    "type": "mrkdwn",
                    "text": (
                        f"*High:*\n"
                        f"{summary['HIGH']}"
                    )
                },
            ]
        },
    ]

    if top_findings:

        finding_lines = []

        for vuln in top_findings:

            finding_lines.append(
                f"• *{vuln['severity']}* "
                f"`{vuln['id']}` — "
                f"{vuln['package']} "
                f"{vuln['installed_version']}"
            )

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*Top CRITICAL/HIGH findings:*\n"
                    + "\n".join(finding_lines)
                )
            }
        })

    else:

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "No CRITICAL or HIGH vulnerabilities found."
            }
        })

    response = requests.post(
        webhook_url,
        json={"blocks": blocks},
        timeout=10
    )

    response.raise_for_status()

    logger.info(
        "Slack notification sent successfully."
    )


def send_teams(
    scan_result: dict,
    vulnerabilities: list
) -> None:
    """
    Send a Microsoft Teams MessageCard notification.
    """

    webhook_url = os.getenv(
        "TEAMS_WEBHOOK_URL"
    )

    if not webhook_url:
        raise RuntimeError(
            "TEAMS_WEBHOOK_URL is not set."
        )

    summary = summarize_vulnerabilities(
        vulnerabilities
    )

    image_name = scan_result.get(
        "ArtifactName",
        "Unknown image"
    )

    theme_color = (
        "C0392B"
        if summary["CRITICAL"] > 0
        else "E67E22"
    )

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": "Container Security Scan",
        "title": "Container Security Scan",
        "sections": [
            {
                "activityTitle": (
                    f"Image: {image_name}"
                ),
                "facts": [
                    {
                        "name": "Total",
                        "value": str(
                            len(vulnerabilities)
                        ),
                    },
                    {
                        "name": "CRITICAL",
                        "value": str(
                            summary["CRITICAL"]
                        ),
                    },
                    {
                        "name": "HIGH",
                        "value": str(
                            summary["HIGH"]
                        ),
                    },
                    {
                        "name": "MEDIUM",
                        "value": str(
                            summary["MEDIUM"]
                        ),
                    },
                    {
                        "name": "Scanned",
                        "value": "Yes",
                    },
                ],
            }
        ],
    }

    response = requests.post(
        webhook_url,
        json=payload,
        timeout=10
    )

    response.raise_for_status()

    logger.info(
        "Teams notification sent successfully."
    )


def main():
    """
    Command-line entry point.
    """

    parser = argparse.ArgumentParser(
        description="Security scan notification sender"
    )

    parser.add_argument(
        "scan_result",
        help="Path to the Trivy scan JSON result"
    )

    parser.add_argument(
        "--channel",
        choices=["slack", "teams", "both"],
        default="both",
        help="Notification channel"
    )

    args = parser.parse_args()

    scan_result = load_scan_result(
        args.scan_result
    )

    vulnerabilities = get_vulnerabilities(
        scan_result
    )

    logger.info(
        f"Loaded {len(vulnerabilities)} vulnerabilities."
    )

    if args.channel in ("slack", "both"):
        send_slack(
            scan_result,
            vulnerabilities
        )

    if args.channel in ("teams", "both"):
        send_teams(
            scan_result,
            vulnerabilities
        )


if __name__ == "__main__":
    main()

import json
import logging
import os
import re
import time
from pathlib import Path

from prometheus_client import Gauge, start_http_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

DATA_DIR = Path(os.getenv("DATA_DIR", "scan_results"))
POLL_SECONDS = max(1, int(os.getenv("POLL_SECONDS", "15")))

VULNERABILITIES_TOTAL = Gauge(
    "vuln_scanner_vulnerabilities_total",
    "Current vulnerabilities by image and severity",
    ["image", "severity"],
)

SCANS_TOTAL = Gauge(
    "vuln_scanner_scans_total",
    "Latest scan status by image: blocked or passed",
    ["image", "status"],
)

LAST_SCAN_TIMESTAMP = Gauge(
    "vuln_scanner_last_scan_timestamp_seconds",
    "Timestamp of the latest scan report by image",
    ["image"],
)

REPORTS_LOADED = Gauge(
    "vuln_scanner_reports_loaded",
    "Number of valid scan reports currently loaded",
)


def safe_image_name(value):
    """Return a usable image name from a report or filename."""
    return str(value or "unknown").strip() or "unknown"


def load_report(path):
    """Read one raw Trivy JSON report and return its metrics."""
    with path.open("r", encoding="utf-8-sig") as file:
        report = json.load(file)

    image = safe_image_name(
        report.get("ArtifactName") or path.stem
    )

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    results = report.get("Results") or []
    for result in results:
        for vulnerability in result.get("Vulnerabilities") or []:
            severity = str(
                vulnerability.get("Severity") or "UNKNOWN"
            ).upper()
            if severity not in counts:
                severity = "UNKNOWN"
            counts[severity] += 1

    created_at = report.get("CreatedAt")
    timestamp = path.stat().st_mtime

    if created_at:
        from datetime import datetime

        try:
            timestamp = datetime.fromisoformat(
                created_at.replace("Z", "+00:00")
            ).timestamp()
        except (ValueError, TypeError):
            logger.warning(
                "Could not parse CreatedAt in %s; using file timestamp",
                path.name,
            )

    # Match the project's existing security gate:
    # only CRITICAL findings block the build.
    status = (
        "blocked" if counts["CRITICAL"] > 0 else "passed"
    )

    return image, counts, timestamp, status


def refresh_metrics():
    """Reload all valid reports and publish their current values."""
    if not DATA_DIR.exists():
        logger.warning("Scan results directory does not exist: %s", DATA_DIR)
        REPORTS_LOADED.set(0)
        return

    reports = sorted(DATA_DIR.glob("*.json"))
    loaded = 0

    # Remove previous label values so removed reports don't stay visible.
    VULNERABILITIES_TOTAL.clear()
    SCANS_TOTAL.clear()
    LAST_SCAN_TIMESTAMP.clear()

    for path in reports:
        try:
            image, counts, timestamp, status = load_report(path)

            for severity, count in counts.items():
                VULNERABILITIES_TOTAL.labels(
                    image=image, severity=severity
                ).set(count)

            SCANS_TOTAL.labels(image=image, status=status).set(1)
            other_status = "passed" if status == "blocked" else "blocked"
            SCANS_TOTAL.labels(
                image=image, status=other_status
            ).set(0)

            LAST_SCAN_TIMESTAMP.labels(image=image).set(timestamp)
            loaded += 1

            logger.info(
                "Loaded %s: %s vulnerabilities; scan status=%s",
                image,
                sum(counts.values()),
                status,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.error("Skipping report %s: %s", path, exc)

    REPORTS_LOADED.set(loaded)
    logger.info("Loaded %s valid report(s)", loaded)


def main():
    """Start the metrics HTTP server and periodically reload reports."""
    port = int(os.getenv("PORT", "8000"))
    start_http_server(port)
    logger.info("Prometheus metrics available on port %s", port)
    logger.info("Monitoring directory: %s", DATA_DIR.resolve())

    while True:
        refresh_metrics()
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()

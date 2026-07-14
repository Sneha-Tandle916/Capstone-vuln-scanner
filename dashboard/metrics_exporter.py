from prometheus_client import Gauge

# Total vulnerabilities found
TOTAL_VULNERABILITIES = Gauge(
    "vulnerability_total",
    "Total vulnerabilities found"
)

# High severity vulnerabilities
HIGH_VULNERABILITIES = Gauge(
    "high_vulnerabilities",
    "High severity vulnerabilities"
)

# Critical severity vulnerabilities
CRITICAL_VULNERABILITIES = Gauge(
    "critical_vulnerabilities",
    "Critical severity vulnerabilities"
)

def update_metrics(vulnerabilities: list):
    """
    Update Prometheus metrics using vulnerability data.
    """

    total = len(vulnerabilities)

    high = sum(
        1 for vuln in vulnerabilities
        if vuln["severity"] == "HIGH"
    )

    critical = sum(
        1 for vuln in vulnerabilities
        if vuln["severity"] == "CRITICAL"
    )

    TOTAL_VULNERABILITIES.set(total)
    HIGH_VULNERABILITIES.set(high)
    CRITICAL_VULNERABILITIES.set(critical)

from prometheus_client import start_http_server


def start_metrics_server(port: int = 8000):
    """
    Start Prometheus metrics server.
    """

    start_http_server(port)

    print(f"Prometheus metrics available at http://localhost:{port}")

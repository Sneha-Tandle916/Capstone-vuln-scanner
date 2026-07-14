from scanner.trivy_runner import scan_image
from scanner.cve_parser import extract_vulnerabilities

from dashboard.metrics_exporter import (
    update_metrics,
    start_metrics_server,
)

import time

print("=" * 60)
print("Starting Prometheus Metrics Server...")
print("=" * 60)

# Start Prometheus server
start_metrics_server()

# Scan Docker image
scan_result = scan_image("alpine:3.19")

# Extract vulnerabilities
vulnerabilities = extract_vulnerabilities(scan_result)

# Update Prometheus metrics
update_metrics(vulnerabilities)

print(f"Total Vulnerabilities : {len(vulnerabilities)}")

print("\nPrometheus is running.")
print("Open http://localhost:8000 in your browser.")
print("Press Ctrl+C to stop the server.")

# Keep the program running
while True:
    time.sleep(5)
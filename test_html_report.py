from scanner.trivy_runner import scan_image
from scanner.cve_parser import extract_vulnerabilities
from reports.report_gen import (
    generate_html_report,
    save_html_report,
)

scan_result = scan_image("alpine:3.19")

vulnerabilities = extract_vulnerabilities(scan_result)

html = generate_html_report(vulnerabilities)

save_html_report(html)

print("HTML report generated successfully!")
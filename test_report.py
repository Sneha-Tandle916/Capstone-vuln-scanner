from scanner.trivy_runner import scan_image
from scanner.cve_parser import extract_vulnerabilities
from reports.report_gen import generate_summary, save_report

scan_result = scan_image("alpine:3.19")

vulnerabilities = extract_vulnerabilities(scan_result)

summary = generate_summary(vulnerabilities)

print(summary)

save_report(summary)
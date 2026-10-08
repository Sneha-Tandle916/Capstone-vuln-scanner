import json
from scanner.cve_parser import extract_vulnerabilities
from reports.report_gen import generate_html_report, save_html_report

with open("test_result.json", "r", encoding="utf-8") as file:
    scan_result = json.load(file)

vulnerabilities = extract_vulnerabilities(scan_result)

print(f"Vulnerabilities loaded: {len(vulnerabilities)}")

html = generate_html_report(vulnerabilities)

save_html_report(
    html,
    "reports/sprint3_test_report.html"
)

print("HTML report generated successfully.")

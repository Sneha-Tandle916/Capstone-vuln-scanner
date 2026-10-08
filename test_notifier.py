import json
from notifications.notifier import get_vulnerabilities, summarize_vulnerabilities

with open("test_result.json", "r", encoding="utf-8") as file:
    scan_result = json.load(file)

vulnerabilities = get_vulnerabilities(scan_result)
summary = summarize_vulnerabilities(vulnerabilities)

print(f"Total vulnerabilities: {len(vulnerabilities)}")
print(f"CRITICAL: {summary['CRITICAL']}")
print(f"HIGH: {summary['HIGH']}")
print(f"MEDIUM: {summary['MEDIUM']}")
print(f"LOW: {summary['LOW']}")
print(f"UNKNOWN: {summary['UNKNOWN']}")
print()
print("Top 5 CRITICAL/HIGH findings:")

top_findings = [
    vuln
    for vuln in vulnerabilities
    if vuln["severity"] in ("CRITICAL", "HIGH")
][:5]

for vuln in top_findings:
    print(
        f"{vuln['severity']} | "
        f"{vuln['id']} | "
        f"{vuln['package']} | "
        f"{vuln['installed_version']}"
    )

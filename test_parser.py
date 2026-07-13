from scanner.trivy_runner import scan_image
from scanner.cve_parser import extract_vulnerabilities

print("Scanning image...")

scan_result = scan_image("alpine:3.19")

vulnerabilities = extract_vulnerabilities(scan_result)

print(f"Total vulnerabilities found: {len(vulnerabilities)}")

if vulnerabilities:
    print("\nFirst vulnerability:")
    for key, value in vulnerabilities[0].items():
        print(f"{key}: {value}")
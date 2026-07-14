from scanner.scan import run_scan

print("Running vulnerability scan...")

vulnerabilities = run_scan("alpine:3.19")

print(f"\nTotal Vulnerabilities: {len(vulnerabilities)}")

if vulnerabilities:
    print("\nFirst Vulnerability:\n")

    for key, value in vulnerabilities[0].items():
        print(f"{key}: {value}")
else:
    print("No vulnerabilities found.")
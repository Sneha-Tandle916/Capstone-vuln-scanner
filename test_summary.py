from scanner.scan import run_scan, summarize_vulnerabilities

print("Running vulnerability scan...")

vulnerabilities = run_scan("alpine:3.19")

summary = summarize_vulnerabilities(vulnerabilities)

print("\nSeverity Summary")
print("-" * 30)

for severity, count in summary.items():
    print(f"{severity:10}: {count}")
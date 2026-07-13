from scanner.trivy_runner import scan_image

print("Starting scan...")

result = scan_image("alpine:3.19")

print("Scan completed successfully!")
print(type(result))
print(result.keys())
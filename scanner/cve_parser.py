import logging

logger = logging.getLogger(__name__)

def extract_vulnerabilities(scan_result: dict) -> list:
    """
    Extract vulnerability details from Trivy JSON output.
    """

    vulnerabilities = []

    results = scan_result.get("Results", [])

    logger.info(f"Found {len(results)} scan result section(s)")

    for result in results:

        vulns = result.get("Vulnerabilities", [])

        logger.info(f"Found {len(vulns)} vulnerabilities")

        for vuln in vulns:

            vulnerability = {
                "id": vuln.get("VulnerabilityID", "N/A"),
                "package": vuln.get("PkgName", "Unknown"),
                "installed_version": vuln.get("InstalledVersion", "Unknown"),
                "fixed_version": vuln.get("FixedVersion", "Not Fixed"),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "title": vuln.get("Title", "No Title"),
            }

            vulnerabilities.append(vulnerability)

    return vulnerabilities
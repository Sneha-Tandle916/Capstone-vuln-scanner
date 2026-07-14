import logging
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


def generate_summary(vulnerabilities: list) -> str:
    """
    Generate a detailed text report.
    """

    total = len(vulnerabilities)

    summary = []
    summary.append("=" * 60)
    summary.append("VULNERABILITY SCAN REPORT")
    summary.append("=" * 60)
    summary.append(f"Total Vulnerabilities Found: {total}")
    summary.append("")

    for vuln in vulnerabilities:

        summary.append("-" * 60)
        summary.append(f"CVE ID            : {vuln['id']}")
        summary.append(f"Package           : {vuln['package']}")
        summary.append(f"Severity          : {vuln['severity']}")
        summary.append(f"Installed Version : {vuln['installed_version']}")
        summary.append(f"Fixed Version     : {vuln['fixed_version']}")
        summary.append(f"Title             : {vuln['title']}")
        summary.append("")

    return "\n".join(summary)


def save_report(report: str, filename: str = "reports/scan_report.txt") -> None:
    """
    Save the generated report to a text file.
    """

    output_path = Path(filename)

    # Create directory if it doesn't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(report)

    logger.info(f"Report saved to {output_path}")


def generate_html_report(vulnerabilities: list,
                         template_dir: str = "templates",
                         template_name: str = "report_template.html") -> str:
    """
    Generate an HTML report using a Jinja2 template.
    """

    env = Environment(
        loader=FileSystemLoader(template_dir)
    )

    template = env.get_template(template_name)

    html = template.render(
        total=len(vulnerabilities),
        vulnerabilities=vulnerabilities
    )

    return html


def save_html_report(html: str,
                     filename: str = "reports/scan_report.html") -> None:
    """
    Save the generated HTML report.
    """

    output_path = Path(filename)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(html)

    logger.info(f"HTML report saved to {output_path}")
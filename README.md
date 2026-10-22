# Capstone Vulnerability Scanner

## Project Overview

The **Capstone Vulnerability Scanner** is an automated container image security scanning solution built using Trivy, Python, Docker, Jenkins, and GitHub Actions.

The project scans container images for known security vulnerabilities, classifies findings by severity, enforces configurable security gates, generates vulnerability reports, and sends Slack notifications when a security gate blocks a build.

The goal is to integrate vulnerability detection into the CI/CD pipeline so that potentially vulnerable container images can be identified before deployment.

## Objectives

- Automate container image vulnerability scanning.
- Identify and classify vulnerabilities by severity.
- Enforce security policies through configurable security gates.
- Generate detailed HTML vulnerability reports.
- Integrate scanning into Jenkins and GitHub Actions.
- Send Slack notifications when security checks fail.
- Archive scan results for investigation and auditing.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Scanner orchestration, parsing, reporting, and notifications |
| Trivy | Container image vulnerability scanning |
| Docker | Container image building and execution |
| Jenkins | CI/CD pipeline automation |
| GitHub Actions | Automated repository workflow |
| PyYAML | Configuration file processing |
| Jinja2 | HTML report generation |
| Requests | Slack webhook notifications |
| Git and GitHub | Version control and source-code hosting |

## Project Structure

```text
Capstone-vuln-scanner/
├── .github/
│   └── workflows/
│       └── scan.yml
├── cicd/
│   └── jenkins/
│       └── Jenkinsfile
├── exceptions/
│   └── whitelist.json
├── notifications/
│   └── notifier.py
├── reports/
│   └── report_gen.py
├── scanner/
│   ├── scan.py
│   ├── trivy_runner.py
│   ├── cve_parser.py
│   └── gate_check.py
├── templates/
│   └── report_template.html
├── config.yaml
├── Dockerfile
├── requirements.txt
├── test_report.py
└── README.md
```

*Note: The structure above shows the main expected project files. Additional test files and supporting modules may also be present in the repository.*

## Key Features

### 1. Automated Vulnerability Scanning

- Uses Trivy to scan container images.
- Collects vulnerability details from scan results.
- Supports severity-based filtering.
- Produces machine-readable JSON scan reports.

### 2. Severity Classification

Vulnerabilities are summarized using the following severity levels:

- CRITICAL
- HIGH
- MEDIUM
- LOW
- UNKNOWN

This classification helps prioritize findings according to their severity.

### 3. Configurable Security Gate

The security gate checks scan results against the configured policy.

The project supports configurable severity settings through `config.yaml`.

Example:

```yaml
severity_threshold: "HIGH,CRITICAL"
fail_on_severity: "CRITICAL"
report_format: "html"
slack_channel: "#security-alerts"
rescan_interval_days: 7
whitelist_path: "exceptions/whitelist.json"
```

The scanner and gate use their respective configuration settings. A build can be blocked when findings meet the configured failure criteria.

### 4. HTML Vulnerability Reports

The reporting module uses Python and Jinja2 to generate an HTML report containing:

- Vulnerability summary
- Severity-based counts
- Detailed vulnerability information
- CVE identifiers and package information

The report provides a convenient way to review scan findings.

### 5. Slack Notifications

The notification module sends Slack messages through an incoming webhook.

Notifications can be used to alert developers when a scan or security gate requires attention.

Configure the webhook using an environment variable named `SLACK_WEBHOOK_URL`. Do not commit the webhook URL or other secrets to GitHub.

### 6. Jenkins CI/CD Integration

The Jenkins pipeline is defined in:

`cicd/jenkins/Jenkinsfile`

The pipeline includes:

1. Checkout source code from GitHub.
2. Create a Python virtual environment.
3. Install Python dependencies.
4. Install Trivy if necessary.
5. Build the scanner Docker image.
6. Run the container image vulnerability scan.
7. Evaluate scan results using the security gate.
8. Archive the scan result.
9. Send a Slack notification on failure.

The security gate can intentionally mark a build as failed when critical vulnerabilities are detected.

### 7. GitHub Actions Integration

The workflow is defined in:

`.github/workflows/scan.yml`

The workflow automates dependency installation, Trivy setup, scanner image building, vulnerability scanning, security gate validation, and scan-result artifact upload.

The workflow can be triggered by configured repository events, scheduled runs, and manual execution where enabled in the workflow file.

## Prerequisites

Install the following tools before running the project locally:

- Python 3.11 or a compatible supported Python version
- Docker Desktop or Docker Engine
- Trivy
- Git
- A Slack workspace and incoming webhook, if Slack notifications are required

Jenkins is required to run the Jenkins pipeline.

## Local Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Sneha-Tandle916/Capstone-vuln-scanner.git
cd Capstone-vuln-scanner
```

### 2. Create a Python Virtual Environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux or macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Configure the Project

Review `config.yaml` and adjust the severity threshold and gate policy according to your requirements.

Make sure Trivy is installed and available on your system's PATH.

## Running a Vulnerability Scan

Run the scanner against a container image:

```bash
python -m scanner.scan python:3.8 --output-json test_result.json
```

This command creates a JSON scan result when the scan completes successfully.

For demonstrations, use an image and tag appropriate for your security policy. The `python:3.8` image used during testing may contain known vulnerabilities and should not automatically be considered suitable for production.

## Running the Security Gate

Evaluate a generated scan report:

```bash
python scanner/gate_check.py test_result.json
```

The gate uses the project's configured severity policy.

The scanner's findings determine whether the gate passes or blocks the build. A nonzero exit code can be used by CI/CD systems to stop the pipeline.

## Generating an HTML Report

Use the report-generation module or the project's report test script:

```bash
python test_report.py
```

The test script generates the HTML report at the path configured by the script, such as:

`reports/sprint3_test_report.html`

Open the generated HTML file in a web browser to review the report.

## Configuring Slack Notifications

Set your Slack incoming webhook URL as an environment variable.

**Windows PowerShell:**

```powershell
$env:SLACK_WEBHOOK_URL = "YOUR_SLACK_WEBHOOK_URL"
```

**Linux or macOS:**

```bash
export SLACK_WEBHOOK_URL="YOUR_SLACK_WEBHOOK_URL"
```

Replace the placeholder locally with your own webhook URL. Never publish the real URL in source code, screenshots, documentation, or commits.

Send a notification for an existing scan result:

```bash
python notifications/notifier.py test_result.json --channel slack
```

The webhook must be configured before running the notification command.

For Jenkins, configure the webhook as a Jenkins Secret text credential with ID:

`slack-webhook-url`

The Jenkinsfile references this credential without embedding the secret in the repository.

## Docker

Build the scanner image from the repository root:

```bash
docker build -t vuln-scanner:local .
```

The image can then be used according to the command and entrypoint configured in the project's Dockerfile.

## GitHub Actions

To review workflow execution:

1. Open the repository on GitHub.
2. Select the **Actions** tab.
3. Open the **Security Scan** workflow.
4. Select a workflow run.
5. Review the scan, security gate, and artifact-upload steps.
6. Download the scan-result artifact when available.

The workflow has been tested successfully, including a run in which the security gate reported:

`GATE PASSED — no CRITICAL+ vulnerabilities`

This result applies to that particular scan and policy; it does not guarantee that every image or future scan will be vulnerability-free.

## Jenkins

The Jenkins pipeline is stored in:

`cicd/jenkins/Jenkinsfile`

The configured Jenkins job checks out the repository and runs the scanning pipeline.

To review a run:

1. Open the Jenkins dashboard.
2. Select `Capstone-Vulnerability-Scanner`.
3. Open the relevant build.
4. Select **Console Output** to review execution details.
5. Open the build's archived `scan_result.json` artifact when available.

A build marked `FAILURE` because of a security-gate violation can indicate that the policy is working as designed.

## Testing and Verification

The following capabilities have been exercised during project development:

- Trivy image scanning
- Python dependency installation
- Severity-based security gate evaluation
- HTML report generation
- Slack webhook notification delivery
- Jenkins pipeline execution
- Jenkins scan-result artifact archiving
- GitHub Actions workflow execution
- Successful security gate validation after updating a vulnerable dependency

## Security Considerations

- Keep webhook URLs and other credentials out of source control.
- Use patched base images and dependencies.
- Review critical and high-severity findings before deployment.
- Keep security gate policies enabled.
- Verify scan reports before approving container images.
- Review exceptions and whitelists regularly.
- Re-run scans periodically because vulnerability databases and image contents change.

## Sprint 3 Deliverables

Sprint 3 focused on enhancing the scanner with reporting, notifications, and CI/CD integration.

The implemented deliverables include:

- HTML vulnerability report generation using Jinja2
- Slack notification integration
- Jenkins pipeline automation
- Security gate execution in CI/CD
- Scan-result artifact archiving
- GitHub Actions workflow validation
- Dependency remediation and security-gate revalidation

## Future Improvements

- Add richer report filtering and sorting.
- Publish reports as HTML artifacts in CI/CD.
- Improve handling of scan errors and unavailable results.
- Add automated dependency updates and scheduled remediation checks.
- Introduce more extensive automated tests.
- Integrate additional notification channels where supported.
- Evaluate newer, supported base-image versions and enforce image-update policies.

## Conclusion

The Capstone Vulnerability Scanner demonstrates how container image vulnerability scanning can be integrated into a CI/CD workflow using Trivy, Python, Docker, Jenkins, and GitHub Actions.

By combining automated scanning, severity-based security gates, HTML reports, Slack notifications, and artifact archiving, the project provides a foundation for identifying and managing container security risks during software delivery.

 

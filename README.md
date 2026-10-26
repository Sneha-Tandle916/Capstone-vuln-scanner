# Capstone Vulnerability Scanner

A DevSecOps project that scans container images for security vulnerabilities using **Trivy**, generates HTML reports, enforces security gates, sends Slack notifications, and visualizes vulnerability metrics through **Prometheus and Grafana**.

## Table of Contents

- [Project Overview](#project-overview)
- [Objectives](#objectives)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Setup and Installation](#setup-and-installation)
- [Run a Vulnerability Scan](#run-a-vulnerability-scan)
- [Security Gate](#security-gate)
- [Generate HTML Reports](#generate-html-reports)
- [Slack Notifications](#slack-notifications)
- [Prometheus and Grafana Monitoring](#prometheus-and-grafana-monitoring)
- [Jenkins CI/CD Pipeline](#jenkins-cicd-pipeline)
- [GitHub Actions](#github-actions)
- [Latest Scan Results](#latest-scan-results)
- [Troubleshooting](#troubleshooting)
- [Future Improvements](#future-improvements)

## Project Overview

The Capstone Vulnerability Scanner automates container image vulnerability detection and integrates security checks into a DevSecOps workflow.

It uses Trivy to identify known vulnerabilities in container images. Scan results can be evaluated by a configurable security gate, presented in HTML reports, and monitored using Prometheus and Grafana. Slack notifications provide feedback about scan execution.

The project demonstrates how security scanning and monitoring can be integrated into a CI/CD pipeline.

## Objectives

- Automate container image vulnerability scanning.
- Identify vulnerabilities by severity.
- Apply configurable security-gate policies.
- Generate readable HTML vulnerability reports.
- Send scan notifications through Slack.
- Integrate scanning with Jenkins and GitHub Actions.
- Expose scan metrics to Prometheus.
- Visualize vulnerability counts and scan status in Grafana.
- Run the monitoring services together using Docker Compose.

## Architecture

```text
Developer
    |
    v
GitHub Repository
    |
    +----------------------+
    |                      |
    v                      v
GitHub Actions           Jenkins
    |                      |
    +----------+-----------+
               |
               v
        Trivy Image Scan
               |
               v
       Scan Result JSON
               |
       +-------+--------+
       |       |        |
       v       v        v
   Security   HTML     Slack
     Gate    Report   Notification
               |
               v
       Metrics Exporter
               |
               v
          Prometheus
               |
               v
            Grafana
```

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Scanner integration, report generation, and metrics exporter |
| Trivy | Container image vulnerability scanning |
| Docker | Container image building and service execution |
| Docker Compose | Running the exporter, Prometheus, and Grafana together |
| Jenkins | CI/CD pipeline automation |
| GitHub Actions | Repository-based automated scanning |
| Prometheus | Collecting and querying monitoring metrics |
| Grafana | Vulnerability dashboard and visualization |
| Slack Webhooks | Scan notification delivery |
| Jinja2 | HTML report templating |
| PyYAML | YAML configuration handling |
| Git and GitHub | Source control and project hosting |

## Project Structure

```text
Capstone-vuln-scanner/
├── .github/
│   └── workflows/
│       └── scan.yml
├── cicd/
│   └── jenkins/
│       └── Jenkinsfile
├── dashboard/
│   ├── metrics_exporter.py
│   ├── prometheus.yml
│   └── grafana_config/
│       ├── datasources/
│       │   └── prometheus.yml
│       └── dashboards/
│           ├── dashboards.yml
│           └── json/
│               └── vuln-scanner.json
├── exceptions/
├── notifications/
│   └── notifier.py
├── reports/
│   └── report_gen.py
├── scanner/
│   ├── scan.py
│   ├── trivy_runner.py
│   └── gate_check.py
├── templates/
├── config.yaml
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

*Note: The tree highlights the main project components. Additional files may be present in the repository.*

## Features

### 1. Container Image Scanning

Trivy scans container images and produces structured JSON vulnerability data.

Example image used during testing:

```text
python:3.8
```

### 2. Severity Classification

The scanner tracks vulnerability severities:

- CRITICAL
- HIGH
- MEDIUM
- LOW
- UNKNOWN

The scan results are used by the reporting, security-gate, notification, and monitoring components.

### 3. Configurable Security Gate

The security gate evaluates scan results according to the project's policy and returns an appropriate exit code:

| Exit code | Meaning |
|---|---|
| `0` | Security gate passed |
| `1` | Security gate blocked the build |
| `2` | Error occurred while evaluating the gate |

The current configuration blocks a build when CRITICAL vulnerabilities are detected.

### 4. HTML Vulnerability Reports

The report generator creates an HTML report with summary cards, severity information, and vulnerability details.

Reports make it easier to inspect scan findings and communicate security risks.

### 5. Slack Notifications

The notification module sends scan-related information to Slack through a configured webhook.

Webhook URLs should be stored in environment variables or CI/CD credentials, not committed to GitHub.

### 6. Prometheus Metrics

The metrics exporter reads JSON scan reports and exposes metrics on port `8000`.

Metrics include:

| Metric | Description |
|---|---|
| `vuln_scanner_vulnerabilities_total` | Vulnerability counts by image and severity |
| `vuln_scanner_scans_total` | Scan status by image, including blocked and passed |
| `vuln_scanner_last_scan_timestamp_seconds` | Timestamp associated with the loaded scan report |
| `vuln_scanner_reports_loaded` | Number of valid reports loaded by the exporter |

The exporter refreshes its metrics periodically, using a default polling interval of 15 seconds.

### 7. Grafana Dashboard

The provisioned dashboard includes:

- Vulnerabilities by severity.
- Blocked scan status.
- Current vulnerability counts.
- Image and severity filters.

The dashboard uses Prometheus as its data source.

## Prerequisites

Install or configure the following tools:

- Python 3.11 or a compatible Python version.
- Docker Desktop with Docker Compose.
- Trivy.
- Git.
- A Slack webhook if Slack notifications are required.
- Jenkins if you want to run the Jenkins pipeline.

The monitoring stack runs in Docker containers.

## Setup and Installation

- [Sprint 6 Deployment and Acceptance Testing](#sprint-6-deployment-and-acceptance-testing)

### 1. Clone the repository

```powershell
git clone https://github.com/Sneha-Tandle916/Capstone-vuln-scanner.git
cd Capstone-vuln-scanner
```

### 2. Create and activate a Python virtual environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use the Python executable directly instead:

```powershell
.\.venv\Scripts\python.exe --version
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Install and verify Trivy

Ensure Trivy is installed and available on your PATH.

```powershell
trivy --version
```

## Run a Vulnerability Scan

Run the scanner against a container image:

```powershell
python -m scanner.scan python:3.8 --output-json scan_result.json
```

The scan output is written to `scan_result.json`.

**Note:** The exact command-line options depend on the current scanner implementation. Use `python -m scanner.scan --help` to inspect the available arguments.

## Security Gate

Evaluate a scan result with the security gate:

```powershell
python scanner/gate_check.py --help
```

Use the supported arguments shown by the help output to evaluate the scan result.

A blocked result is an intentional security-policy outcome when findings exceed the configured threshold. It should not automatically be treated as a scanner malfunction.

## Generate HTML Reports

The report generator is located at:

```text
reports/report_gen.py
```

The project uses Jinja2 templates to create an HTML report with vulnerability summaries and detailed findings.

For the exact report-generation command, refer to the current CLI help or the test script in the repository.

## Slack Notifications

The notification module is located at:

```text
notifications/notifier.py
```

The CLI supports selecting a notification channel.

Example:

```powershell
python notifications/notifier.py --help
```

To send a notification using a scan-result file, use the supported command syntax:

```powershell
python notifications/notifier.py scan_result.json --channel slack
```

The Slack webhook must be configured before sending notifications. In Jenkins, store the webhook as a credential and expose it to the pipeline securely.

Never place a real webhook URL or secret directly in this README.

## Prometheus and Grafana Monitoring

Sprint 4 integrates the scanner with a Prometheus and Grafana monitoring stack.

### 1. Ensure scan data is available

The Docker Compose configuration mounts the local `scan_results/` directory into the exporter container as `/data`.

Place a valid Trivy JSON report in the local `scan_results/` directory before starting the stack. For example:

```text
scan_results/
└── python_3.8.json
```

The directory is intentionally excluded from Git because scan reports can be large and may contain generated data.

### 2. Build and start the services

Run from the project root:

```powershell
docker compose build
docker compose up -d
```

### 3. Check the services

```powershell
docker compose ps
```

View exporter logs:

```powershell
docker compose logs --tail 50 vuln-scanner
```

View Prometheus logs:

```powershell
docker compose logs --tail 50 prometheus
```

View Grafana logs:

```powershell
docker compose logs --tail 50 grafana
```

### 4. Open the monitoring interfaces

| Service | URL |
|---|---|
| Metrics exporter | http://localhost:8000/metrics |
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3000 |

The Grafana dashboard is provisioned automatically from the JSON file in `dashboard/grafana_config/dashboards/json/`.

The local Grafana administrator password is configured through the Docker Compose environment. The current development configuration uses `admin`; change it before exposing the service to other users or networks.

### 5. Verify Prometheus metrics

Open the Prometheus web interface and execute:

```promql
vuln_scanner_vulnerabilities_total
```

To aggregate vulnerability counts by severity:

```promql
sum by (severity) (
  vuln_scanner_vulnerabilities_total
)
```

The results should correspond to the scan reports currently loaded by the exporter.

### 6. View Grafana

Open:

```text
http://localhost:3000
```

Sign in using the configured local credentials and open the **Vulnerability Scanner Dashboard**.

The dashboard provides vulnerability visualizations and scan-status information.

### 7. Stop the monitoring stack

```powershell
docker compose down
```

To stop the services and retain their named data volumes, do not add the `-v` option.

## Jenkins CI/CD Pipeline

The project includes a Jenkins pipeline that automates key vulnerability-scanning tasks.

The pipeline stages include:

1. Checkout source code from GitHub.
2. Install Python dependencies.
3. Install or verify Trivy.
4. Build the scanner Docker image.
5. Run the vulnerability scan.
6. Archive available build artifacts.
7. Send Slack notifications.
8. Evaluate the security gate.

A build can be marked as failed when the security gate detects CRITICAL vulnerabilities. This is expected under the current policy, even if the scan, report generation, and Slack notification steps have succeeded.

## GitHub Actions

The workflow is located at:

```text
.github/workflows/scan.yml
```

The configured workflow supports repository push and pull-request events, scheduled scanning, and manual execution.

Review the GitHub Actions tab in the repository to inspect individual workflow runs and their logs.

## Latest Scan Results

The latest scan report used for Sprint 4 monitoring contains the following results for `python:3.8`:

| Severity | Count |
|---|---:|
| CRITICAL | 238 |
| HIGH | 2,540 |
| MEDIUM | 0 |
| LOW | 0 |
| UNKNOWN | 0 |
| **Total** | **2,778** |

### Interpretation

- The exporter successfully loaded one valid scan report.
- Prometheus successfully collected the vulnerability metrics.
- Grafana displayed the severity counts and blocked scan status.
- The security gate blocked the build because CRITICAL vulnerabilities were present.

These figures represent the specific scan report used during project validation. Results may change when the image or vulnerability database is updated.

## Troubleshooting

### Grafana shows no data

1. Confirm that the exporter container is running.
2. Open `http://localhost:8000/metrics`.
3. Confirm that the expected metrics are present.
4. Open Prometheus and check the `vuln_scanner_vulnerabilities_total` query.
5. Verify the Grafana Prometheus data source URL is `http://prometheus:9090`.
6. Confirm the dashboard queries and image filter match the loaded report.

### The exporter loads no reports

1. Confirm that `scan_results/` exists.
2. Ensure the directory contains valid Trivy JSON files.
3. Check that the directory is mounted to `/data` in Docker Compose.
4. Inspect the exporter logs.

### The Jenkins build is blocked

Inspect the security-gate output to identify the severities causing the failure. Under the current policy, CRITICAL findings block the build. Review and remediate vulnerabilities where possible instead of bypassing the gate simply to obtain a successful build.

### Slack notifications fail

Verify the Jenkins credential, webhook configuration, and network connectivity. Do not print or commit the webhook secret in logs or source files.

## Sprint 6 Deployment and Acceptance Testing

Sprint 6 adds a deployment script and validates the monitoring stack and existing automated tests.

### Deployment Script

The `deploy.sh` script automates the following tasks in a compatible Ubuntu/WSL environment:

- Checks required project files and tools.
- Creates a dedicated Python virtual environment outside the repository.
- Installs Python dependencies from `requirements.txt`.
- Validates `config.yaml` and severity settings.
- Checks for Trivy and installs it if necessary.
- Creates the `scan_results/` directory.
- Builds and starts the scanner metrics exporter, Prometheus, and Grafana using Docker Compose.

### Run the Deployment

From the project root in Ubuntu/WSL:

```bash
chmod +x deploy.sh
./deploy.sh
```

The script requires Docker Desktop integration with the WSL distribution and may require `sudo` when installing Trivy.

### Verify Deployment

Check service status:

```bash
docker compose ps
```

Check the metrics exporter:

```bash
curl -sS -o /dev/null -w 'Metrics HTTP %{http_code}\n' http://localhost:8000/metrics
```

Check Prometheus:

```bash
curl -sS -o /dev/null -w 'Prometheus HTTP %{http_code}\n' http://localhost:9090/-/healthy
```

Check Grafana:

```bash
curl -sS -o /dev/null -w 'Grafana HTTP %{http_code}\n' http://localhost:3000/api/health
```

The validated local deployment returned HTTP 200 for all three endpoints.

### Automated Acceptance Tests

Run the existing automated tests from the project root in PowerShell:

```powershell
python -m pytest -v tests
```

**Validated result:** 9 tests passed. The tests cover vulnerability severity summaries, configuration settings, security-gate pass/block behavior, and whitelist exception expiry handling.

### Service URLs

| Service | URL |
|---|---|
| Metrics exporter | http://localhost:8000/metrics |
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3000 |

### Stop the Monitoring Stack

```bash
docker compose down
```

This stops the services while retaining named Docker volumes.

### Acceptance-Test Scope

The local monitoring deployment and existing automated tests have been validated. GitHub Actions and Jenkins are separate CI/CD validation paths. A fresh-clone clean-room test must also be completed before claiming that the entire Sprint 6 acceptance process is finished.

## Future Improvements

- Add automated remediation guidance for vulnerable packages.
- Track scan history and trends over time.
- Add alerting rules for new CRITICAL vulnerabilities.
- Add report retention and cleanup policies.
- Improve dashboard filtering and historical visualizations.
- Add tests for exporter metrics and security-gate edge cases.
- Evaluate image updates and dependency upgrades to reduce vulnerability findings.


## Conclusion

This capstone demonstrates a practical DevSecOps workflow combining container vulnerability scanning, security-gate enforcement, HTML reporting, Slack notifications, CI/CD automation, and Prometheus–Grafana monitoring.

The monitoring integration was validated against a Trivy scan report, and the Sprint 4 implementation was committed and pushed to GitHub.

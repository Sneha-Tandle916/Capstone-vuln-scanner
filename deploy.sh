#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "=== Capstone Vulnerability Scanner Deployment ==="
echo "Project directory: $ROOT_DIR"

# Check required project files and tools.
for file in requirements.txt config.yaml docker-compose.yml Dockerfile; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Required file not found: $file"
        exit 1
    fi
done

for tool in python3 docker; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $tool"
        exit 1
    fi
done

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker Desktop is not reachable from this WSL distribution."
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: Docker Compose plugin is unavailable."
    exit 1
fi

# Create a dedicated Python environment outside the repository.
VENV_DIR="$HOME/.venvs/capstone-vuln-scanner"
mkdir -p "$(dirname "$VENV_DIR")"

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    python3 -m venv "$VENV_DIR"
fi

echo "Installing Python dependencies..."
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -r requirements.txt

# Validate YAML configuration.
echo "Validating config.yaml..."
"$VENV_DIR/bin/python" - <<'PY'
import yaml

with open("config.yaml", encoding="utf-8") as file:
    config = yaml.safe_load(file)

if not isinstance(config, dict):
    raise SystemExit("ERROR: config.yaml must contain a YAML mapping.")

allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

threshold = config.get("severity_threshold", "HIGH,CRITICAL")
if isinstance(threshold, str):
    severities = {item.strip().upper() for item in threshold.split(",")}
else:
    raise SystemExit("ERROR: severity_threshold must be a comma-separated string.")

if not severities or not severities.issubset(allowed):
    raise SystemExit("ERROR: severity_threshold contains an invalid severity.")

fail_level = str(config.get("fail_on_severity", "CRITICAL")).strip().upper()
if fail_level not in allowed:
    raise SystemExit("ERROR: fail_on_severity contains an invalid severity.")

print("Configuration YAML and severity settings are valid.")
PY

# Install Trivy in Ubuntu if it is missing.
if ! command -v trivy >/dev/null 2>&1; then
    echo "Trivy is not installed. Installing it from the official repository..."
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: sudo is required to install Trivy."
        exit 1
    fi

    sudo apt-get update
    sudo apt-get install -y wget gnupg ca-certificates

    sudo install -d -m 0755 /etc/apt/keyrings
    wget -qO- https://aquasecurity.github.io/trivy-repo/deb/public.key |
        sudo gpg --dearmor --yes -o /etc/apt/keyrings/trivy.gpg

    . /etc/os-release
    echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb ${VERSION_CODENAME} main" |
        sudo tee /etc/apt/sources.list.d/trivy.list >/dev/null

    sudo apt-get update
    sudo apt-get install -y trivy
fi

echo "Trivy version:"
trivy --version

# Ensure the directory mounted by the metrics exporter exists.
mkdir -p scan_results

# Build and start the existing monitoring stack.
echo "Building and starting scanner, Prometheus, and Grafana..."
docker compose up -d --build vuln-scanner prometheus grafana

echo
echo "=== Deployment command completed ==="
docker compose ps
echo
echo "Service URLs:"
echo "  Grafana:    http://localhost:3000"
echo "  Prometheus: http://localhost:9090"
echo "  Metrics:    http://localhost:8000/metrics"
echo
echo "Grafana default username: admin"
echo "Grafana password is configured in docker-compose.yml."
echo "Check service readiness with: docker compose ps"

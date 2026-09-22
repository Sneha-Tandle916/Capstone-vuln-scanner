import subprocess
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def scan_image(image_name: str, severity: str = "HIGH,CRITICAL") -> dict:
    """
    Scan a Docker image using Trivy and return the JSON result.
    """

    cmd = [
        "trivy",
        "image",
        "--format",
        "json",
        "--severity",
        severity,
        "--exit-code",
        "0",
        image_name,
    ]

    logger.info(f"Scanning image: {image_name}")
    result = subprocess.run(
    	cmd,
    	capture_output=True,
    	text=True,
    	encoding="utf-8",
    	errors="replace"
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Trivy failed: {result.stderr.strip()}"
        )
    if not result.stdout.strip():
        raise RuntimeError(
            "Empty output - Is Docker running?"
        )

    return json.loads(result.stdout)
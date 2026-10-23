
# scripts/needs_rescan.py
# Exit 0 when a rescan is due; exit 1 when the scan is fresh.

import datetime
import os
import sys
import yaml


def main() -> int:
    if len(sys.argv) != 2:
        print(
            "Usage: python scripts\\needs_rescan.py <scan_result.json>",
            file=sys.stderr,
        )
        return 2

    result_path = sys.argv[1]

    if not os.path.isfile(result_path):
        print(f"ERROR: scan result not found: {result_path}", file=sys.stderr)
        return 2

    with open("config.yaml", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    interval = int(config.get("rescan_interval_days", 7))
    if interval < 0:
        print("ERROR: rescan_interval_days cannot be negative", file=sys.stderr)
        return 2

    last_scan = datetime.date.fromtimestamp(
        os.path.getmtime(result_path)
    )
    age = (datetime.date.today() - last_scan).days

    if age >= interval:
        print(f"RESCAN DUE: last scan {age} days ago (interval {interval})")
        return 0

    print(f"Scan is fresh: {age} days old (interval {interval})")
    return 1


if __name__ == "__main__":
    sys.exit(main())

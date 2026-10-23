
# scanner/exceptions.py
# Sprint 5: CVE exception handling with expiry enforcement.

import datetime
import json
import sys


def load_whitelist(path: str = "exceptions/whitelist.json") -> set:
    """Return CVE IDs with valid, unexpired exception dates."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print(
            f"WARNING: whitelist not loaded ({path}): {e}",
            file=sys.stderr,
        )
        return set()

    today = datetime.date.today().isoformat()
    active = set()

    for entry in data.get("approved_cves", []):
        cve_id = entry.get("cve_id")
        expiry = entry.get("expiry")

        if not cve_id or not expiry:
            print(
                f"WARNING: ignoring whitelist entry without "
                f"cve_id/expiry: {entry}",
                file=sys.stderr,
            )
            continue

        try:
            # Reject invalid date formats rather than accepting them.
            datetime.date.fromisoformat(expiry)
        except (TypeError, ValueError):
            print(
                f"WARNING: ignoring invalid expiry date: {expiry}",
                file=sys.stderr,
            )
            continue

        if expiry >= today:
            active.add(cve_id)

    return active


def apply_exceptions(vulns: list, whitelist: set) -> tuple:
    """Split findings into active and excepted lists; delete nothing."""
    active = [
        v for v in vulns
        if v.get("cve_id") not in whitelist
    ]
    excepted = [
        v for v in vulns
        if v.get("cve_id") in whitelist
    ]

    return active, excepted

import json

from scanner.scan import summarize_vulnerabilities, load_config
from scanner.gate_check import check_gate


def test_summarize_vulnerability_severities():
    vulnerabilities = [
        {"severity": "CRITICAL"},
        {"severity": "HIGH"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
        {"severity": "LOW"},
        {"severity": "UNKNOWN"},
    ]

    summary = summarize_vulnerabilities(vulnerabilities)

    assert summary == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 1,
        "LOW": 1,
        "UNKNOWN": 1,
    }


def test_summarize_empty_vulnerability_list():
    summary = summarize_vulnerabilities([])

    assert all(count == 0 for count in summary.values())


def test_load_config_contains_security_settings():
    config = load_config()

    assert "severity_threshold" in config
    assert "fail_on_severity" in config
    assert "whitelist_path" in config


def test_gate_passes_for_clean_report(tmp_path, monkeypatch):
    report_path = tmp_path / "clean-report.json"
    report_path.write_text(
        json.dumps({
            "ArtifactName": "sprint5-test-image",
            "Results": [],
        }),
        encoding="utf-8",
    )

    whitelist_path = tmp_path / "whitelist.json"
    whitelist_path.write_text(
        json.dumps({"approved_cves": []}),
        encoding="utf-8",
    )

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "fail_on_severity: CRITICAL\n"
        f"whitelist_path: '{whitelist_path.as_posix()}'\n",
        encoding="utf-8",
    )

    with monkeypatch.context() as patch:
        patch.setattr(
            "sys.argv",
            ["gate_check", str(report_path), "--config", str(config_path)],
        )

        # check_gate takes report and config paths directly.
        try:
            check_gate(str(report_path), str(config_path))
        except SystemExit as exc:
            assert exc.code == 0
def test_gate_blocks_active_critical_vulnerability(tmp_path):
    report_path = tmp_path / "critical-report.json"
    report_path.write_text(
        json.dumps({
            "ArtifactName": "sprint5-critical-test-image",
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-TEST-0001",
                            "Severity": "CRITICAL",
                            "PkgName": "test-package",
                            "InstalledVersion": "1.0",
                            "FixedVersion": "1.1",
                        }
                    ]
                }
            ],
        }),
        encoding="utf-8",
    )

    whitelist_path = tmp_path / "whitelist.json"
    whitelist_path.write_text(
        json.dumps({"approved_cves": []}),
        encoding="utf-8",
    )

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "fail_on_severity: CRITICAL\n"
        f"whitelist_path: '{whitelist_path.as_posix()}'\n",
        encoding="utf-8",
    )

    try:
        check_gate(str(report_path), str(config_path))
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("Expected the gate to block the critical finding")


import datetime
import json

from scanner.exceptions import load_whitelist, apply_exceptions


def test_load_whitelist_accepts_future_expiry(tmp_path):
    whitelist_path = tmp_path / "whitelist.json"
    future_date = (
        datetime.date.today() + datetime.timedelta(days=30)
    ).isoformat()

    whitelist_path.write_text(
        json.dumps({
            "approved_cves": [
                {
                    "cve_id": "CVE-TEST-0001",
                    "expiry": future_date,
                }
            ]
        }),
        encoding="utf-8",
    )

    assert load_whitelist(str(whitelist_path)) == {
        "CVE-TEST-0001"
    }


def test_load_whitelist_ignores_expired_exception(tmp_path):
    whitelist_path = tmp_path / "whitelist.json"
    expired_date = (
        datetime.date.today() - datetime.timedelta(days=1)
    ).isoformat()

    whitelist_path.write_text(
        json.dumps({
            "approved_cves": [
                {
                    "cve_id": "CVE-TEST-0002",
                    "expiry": expired_date,
                }
            ]
        }),
        encoding="utf-8",
    )

    assert load_whitelist(str(whitelist_path)) == set()


def test_load_whitelist_ignores_invalid_expiry(tmp_path):
    whitelist_path = tmp_path / "whitelist.json"

    whitelist_path.write_text(
        json.dumps({
            "approved_cves": [
                {
                    "cve_id": "CVE-TEST-0003",
                    "expiry": "not-a-date",
                }
            ]
        }),
        encoding="utf-8",
    )

    assert load_whitelist(str(whitelist_path)) == set()


def test_apply_exceptions_separates_active_and_excepted():
    vulnerabilities = [
        {"cve_id": "CVE-TEST-0001", "severity": "CRITICAL"},
        {"cve_id": "CVE-TEST-0002", "severity": "HIGH"},
    ]

    active, excepted = apply_exceptions(
        vulnerabilities,
        {"CVE-TEST-0001"},
    )

    assert active == [
        {"cve_id": "CVE-TEST-0002", "severity": "HIGH"}
    ]
    assert excepted == [
        {"cve_id": "CVE-TEST-0001", "severity": "CRITICAL"}
    ]
    assert len(active) + len(excepted) == len(vulnerabilities)



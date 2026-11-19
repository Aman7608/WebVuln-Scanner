"""Tests for the SQLite database and the full scan engine."""

import pytest

from database import db
from scanner.analysis.findings_collector import Finding
from scanner.engine.scan_engine import build_config, create_scan, run_scan
from scanner.target_manager import TargetError


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "test.db")
    db.init_db(path)
    return path


def test_store_and_read_scan(db_path):
    target_id = db.get_or_create_target(db_path, "http://localhost/", "localhost")
    assert db.get_or_create_target(db_path, "http://localhost/", "localhost") == target_id

    scan_id = db.create_scan(db_path, target_id, {"max_depth": 1})
    db.save_discovered_urls(db_path, scan_id, [{"url": "http://localhost/", "status_code": 200, "depth": 0}], "crawler")
    finding = Finding("Test", "reflected_xss", "http://localhost/", "q", "High", "d", "e", "r",
                      severity="High", risk_score=16)
    db.save_findings(db_path, scan_id, [finding])
    db.finish_scan(db_path, scan_id, pages_found=1, requests_sent=5)

    scan = db.get_scan(db_path, scan_id)
    assert scan["status"] == "completed"
    assert scan["finding_count"] == 1
    assert scan["config"] == {"max_depth": 1}
    assert scan["finished_at"]
    assert db.get_findings(db_path, scan_id)[0]["parameter"] == "q"
    assert db.severity_counts(db_path)["High"] == 1
    assert db.dashboard_stats(db_path)["total_scans"] == 1
    assert len(db.list_scans(db_path)) == 1


def test_sql_values_are_parameterized(db_path):
    # A target URL containing SQL must be stored as plain text
    tricky = "http://localhost/?q=');DROP TABLE scans;--"
    target_id = db.get_or_create_target(db_path, tricky, "localhost")
    db.create_scan(db_path, target_id, {})
    assert db.list_scans(db_path)[0]["target_url"] == tricky


def test_unfinished_scans_marked_failed(db_path):
    target_id = db.get_or_create_target(db_path, "http://localhost/", "localhost")
    scan_id = db.create_scan(db_path, target_id, {})
    db.mark_unfinished_scans_failed(db_path)
    assert db.get_scan(db_path, scan_id)["status"] == "failed"


def test_build_config_limits_values():
    config = build_config({"max_depth": "99", "max_pages": "-5", "timeout": "abc",
                           "delay": "0", "modules": ["xss", "rm -rf"]})
    assert config["max_depth"] == 5
    assert config["max_pages"] == 1
    assert config["timeout"] == 10
    assert config["modules"] == ["xss"]


def test_create_scan_rejects_unauthorized_target(db_path):
    with pytest.raises(TargetError):
        create_scan(db_path, "https://example.com/", build_config({}))


def test_full_scan_against_lab(db_path, lab_url):
    config = build_config({"max_depth": 2, "max_pages": 40, "delay": 0})
    scan_id, target = create_scan(db_path, lab_url + "/", config)
    run_scan(db_path, scan_id, target, config)

    scan = db.get_scan(db_path, scan_id)
    assert scan["status"] == "completed", scan["error_message"]
    assert scan["pages_found"] >= 10

    findings = db.get_findings(db_path, scan_id)
    found = {(f["vuln_type"], f["url"].replace(lab_url, ""), f["parameter"]) for f in findings}
    expected = {
        ("reflected_xss", "/search", "q"),
        ("reflected_xss", "/profile", "name"),
        ("sql_injection", "/product", "id"),
        ("sql_injection", "/login", "username"),
        ("open_redirect", "/goto", "url"),
        ("sensitive_file", "/.env", ""),
        ("missing_csp", "/", "Content-Security-Policy"),
    }
    assert expected <= found

    # The safe twin pages must not appear in any injection finding
    for vuln_type, path, _ in found:
        if vuln_type in ("reflected_xss", "sql_injection", "open_redirect"):
            assert path not in ("/safe-search", "/product-safe", "/safe-goto", "/contact")

    # Worst findings come first
    assert findings[0]["severity"] == "Critical"
    sources = {u["source"] for u in db.get_discovered_urls(db_path, scan_id)}
    assert sources == {"crawler", "directory"}


def test_scan_stops_cleanly_at_request_limit(db_path, lab_url):
    config = build_config({"max_requests": 10, "delay": 0})
    scan_id, target = create_scan(db_path, lab_url + "/", config)
    run_scan(db_path, scan_id, target, config)
    scan = db.get_scan(db_path, scan_id)
    assert scan["status"] == "completed"
    assert scan["requests_sent"] <= 10

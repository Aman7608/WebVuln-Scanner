"""Tests for the SQLite database and the full scan engine."""

import pytest

from database import db
from scanner.analysis.findings_collector import Finding
from scanner.engine.scan_engine import build_config, create_scan, run_scan
from scanner.target_manager import TargetError

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


def test_scans_of_a_dead_worker_are_marked_failed(db_path):
    target_id = db.get_or_create_target(db_path, "http://localhost/", "localhost")
    scan_id = db.create_scan(db_path, target_id, {})
    assert db.claim_next_scan(db_path) == scan_id          # now "running"
    db.fail_stale_scans(db_path, minutes=0)
    assert db.get_scan(db_path, scan_id)["status"] == "failed"


def test_old_version_database_is_upgraded(tmp_path):
    """A database made by version 1 (no accounts) still opens and keeps its scans."""
    import sqlite3
    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.executescript("""
        CREATE TABLE targets (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE,
                              host TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL,
            status TEXT NOT NULL, progress INTEGER NOT NULL DEFAULT 0, current_step TEXT DEFAULT '',
            config_json TEXT NOT NULL, pages_found INTEGER NOT NULL DEFAULT 0,
            requests_sent INTEGER NOT NULL DEFAULT 0, error_message TEXT DEFAULT '',
            started_at TEXT NOT NULL, finished_at TEXT);
        INSERT INTO targets VALUES (1, 'http://127.0.0.1:5001/', '127.0.0.1', '2026-11-20 10:00:00');
        INSERT INTO scans (target_id, status, config_json, started_at)
            VALUES (1, 'completed', '{}', '2026-11-20 10:00:00'), (1, 'pending', '{}', '2026-11-20 10:05:00');
    """)
    old.close()
    db.init_db(path)
    scans = db.list_scans(path)
    assert [s["status"] for s in scans] == ["failed", "completed"]   # "pending" can never finish
    user_id = db.create_user(path, "me@example.com", "hash")
    db.claim_orphan_scans(path, user_id)
    assert len(db.list_scans(path, user_id=user_id)) == 2


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


def test_full_scan_with_login_and_stored_xss(db_path, lab_url, monkeypatch):
    from scanner.engine.scan_engine import ALL_MODULES, build_secrets
    from test_lab.vulnerable_app import LAB_PASSWORD, LAB_USERNAME

    monkeypatch.setattr("config.settings.SQLI_TIME_DELAY", 1)
    form = {"max_depth": 3, "max_pages": 60, "delay": 0, "modules": ALL_MODULES,
            "login_url": lab_url + "/account/login", "login_username": LAB_USERNAME,
            "login_password": LAB_PASSWORD}
    config = build_config(form)
    scan_id, target = create_scan(db_path, lab_url + "/", config)
    run_scan(db_path, scan_id, target, config, build_secrets(form))

    scan = db.get_scan(db_path, scan_id)
    assert scan["status"] == "completed", scan["error_message"]
    # The password is never stored, only the username
    assert "login_password" not in scan["config"]
    assert LAB_PASSWORD not in str(scan)

    found = {(f["vuln_type"], f["url"].replace(lab_url, ""), f["parameter"])
             for f in db.get_findings(db_path, scan_id)}
    assert ("reflected_xss", "/account/notes", "title") in found      # behind the login
    assert ("stored_xss", "/guestbook", "message") in found
    assert ("sql_injection", "/order", "id") in found                  # time-based
    assert ("sql_injection", "/api/items", "search") in found          # found via JavaScript


def test_scan_fails_clearly_with_wrong_password(db_path, lab_url):
    from scanner.engine.scan_engine import build_secrets
    form = {"login_url": lab_url + "/account/login", "login_username": "tester",
            "login_password": "wrong", "delay": 0}
    config = build_config(form)
    scan_id, target = create_scan(db_path, lab_url + "/", config)
    run_scan(db_path, scan_id, target, config, build_secrets(form))
    scan = db.get_scan(db_path, scan_id)
    assert scan["status"] == "failed"
    assert "Login failed" in scan["error_message"]


def test_login_page_must_be_on_target(db_path, lab_url):
    config = build_config({"login_url": "https://example.com/login", "login_username": "x"})
    with pytest.raises(TargetError, match="same website"):
        create_scan(db_path, lab_url + "/", config)

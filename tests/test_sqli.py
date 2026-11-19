"""Tests for the SQL injection scanner against the local test lab."""

from scanner.analysis.findings_collector import FindingsCollector
from scanner.crawler.crawler import InjectionPoint
from scanner.vulnerabilities.sqli_scanner import find_database_error, scan_sqli, similarity


def point(lab_url, path, params, method="GET", test_params=None):
    return InjectionPoint(method, lab_url + path, params, "url", lab_url + path,
                          test_params=test_params or [])


def test_error_signatures():
    assert find_database_error("You have an error in your SQL syntax near ''")[0] == "MySQL"
    assert find_database_error("sqlite3.OperationalError: unrecognized token")[0] == "SQLite"
    assert find_database_error("ORA-01756: quoted string not properly terminated")[0] == "Oracle"
    assert find_database_error("Welcome to our shop") is None


def test_similarity():
    assert similarity("abc" * 100, "abc" * 100) == 1.0
    assert similarity("abc" * 100, "xyz" * 100) < 0.2


def test_detects_error_based_sqli_in_url(handler, lab_url):
    collector = FindingsCollector()
    scan_sqli(handler, [point(lab_url, "/product", {"id": "1"})], collector)
    assert len(collector.findings) == 1
    finding = collector.findings[0]
    assert finding.parameter == "id"
    assert finding.confidence == "High"
    assert finding.severity == "Critical"
    assert "SQLite" in finding.evidence


def test_detects_sqli_in_login_form(handler, lab_url):
    collector = FindingsCollector()
    login = point(lab_url, "/login", {"username": "", "password": ""}, method="POST")
    scan_sqli(handler, [login], collector)
    assert {f.parameter for f in collector.findings} == {"username", "password"}


def test_no_false_positive_on_safe_query(handler, lab_url):
    collector = FindingsCollector()
    scan_sqli(handler, [point(lab_url, "/product-safe", {"id": "1"}),
                        point(lab_url, "/safe-search", {"q": "laptop"})], collector)
    assert collector.findings == []


def test_detects_time_based_blind_sqli(handler, lab_url, monkeypatch):
    # Use a 1 second delay so the test stays fast
    monkeypatch.setattr("config.settings.SQLI_TIME_DELAY", 1)
    collector = FindingsCollector()
    scan_sqli(handler, [point(lab_url, "/order", {"id": "1"})], collector)
    assert len(collector.findings) == 1
    finding = collector.findings[0]
    assert finding.name == "SQL Injection (time-based blind)"
    assert finding.confidence == "High"
    assert "SLEEP(1)" in finding.evidence


def test_detects_sqli_in_json_api(handler, lab_url):
    collector = FindingsCollector()
    scan_sqli(handler, [point(lab_url, "/api/items", {"search": ""})], collector)
    assert [f.parameter for f in collector.findings] == ["search"]

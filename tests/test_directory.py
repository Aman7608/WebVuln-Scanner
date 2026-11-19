"""Tests for directory discovery."""

from scanner.analysis.findings_collector import FindingsCollector
from scanner.vulnerabilities.directory_scanner import redact_secrets, scan_directories


def test_redact_secrets():
    text = "APP_ENV=lab\nSECRET_KEY=super-secret\ndefine('DB_PASSWORD', 'hunter2');"
    hidden = redact_secrets(text)
    assert "super-secret" not in hidden and "hunter2" not in hidden
    assert "SECRET_KEY=****" in hidden


def test_finds_exposed_files_in_lab(handler, lab_url):
    collector = FindingsCollector()
    checked = scan_directories(handler, lab_url + "/", collector)
    found = {f.url.replace(lab_url, ""): f for f in collector.findings}

    assert found["/.env"].severity == "Critical"
    assert "fake-lab-secret" not in found["/.env"].evidence   # secret was hidden
    assert found["/backup/"].confidence == "High"              # directory listing
    assert found["/robots.txt"].severity == "Informational"
    assert "/.git/HEAD" not in found                           # returns 404 in the lab
    # Every checked path has its status code recorded
    codes = {c["url"].replace(lab_url, ""): c["status_code"] for c in checked}
    assert codes["/.git/HEAD"] == 404 and codes["/.env"] == 200

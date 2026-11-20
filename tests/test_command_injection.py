"""Tests for the time-based command injection check."""

import pytest

from scanner.analysis.findings_collector import FindingsCollector
from scanner.crawler.crawler import InjectionPoint
from scanner.vulnerabilities.command_injection_scanner import scan_command_injection


@pytest.fixture(autouse=True)
def short_delay(monkeypatch):
    # 1 second instead of 3 keeps the tests fast
    monkeypatch.setattr("config.settings.SQLI_TIME_DELAY", 1)


def point(lab_url, path, params):
    return InjectionPoint("GET", lab_url + path, params, "url", lab_url + path)


def test_detects_command_injection(handler, lab_url):
    collector = FindingsCollector()
    scan_command_injection(handler, [point(lab_url, "/ping", {"host": "127.0.0.1"})], collector)
    assert len(collector.findings) == 1
    finding = collector.findings[0]
    assert finding.parameter == "host"
    assert finding.severity == "Critical"
    assert "sleep 1" in finding.evidence and "sleep 0" in finding.evidence


def test_no_false_positive_on_safe_pages(handler, lab_url):
    collector = FindingsCollector()
    scan_command_injection(handler, [point(lab_url, "/ping-safe", {"host": "127.0.0.1"}),
                                     point(lab_url, "/search", {"q": "laptop"})], collector)
    assert collector.findings == []

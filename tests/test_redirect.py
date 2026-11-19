"""Tests for the open redirect scanner."""

from scanner.analysis.findings_collector import FindingsCollector
from scanner.crawler.crawler import InjectionPoint
from scanner.vulnerabilities.redirect_scanner import (
    looks_like_redirect_param, points_to_test_domain, scan_redirects,
)


def point(lab_url, path, params):
    return InjectionPoint("GET", lab_url + path, params, "url", lab_url + path)


def test_param_name_detection():
    assert looks_like_redirect_param("next", "")
    assert looks_like_redirect_param("whatever", "https://site/")
    assert not looks_like_redirect_param("q", "laptop")


def test_location_check():
    assert points_to_test_domain("https://example.com/x", "http://127.0.0.1/")
    assert points_to_test_domain("//example.com/x", "http://127.0.0.1/")
    assert not points_to_test_domain("/about", "http://127.0.0.1/")
    assert not points_to_test_domain("https://example.com.evil.test/", "http://127.0.0.1/")


def test_detects_open_redirect(handler, lab_url):
    collector = FindingsCollector()
    scan_redirects(handler, [point(lab_url, "/goto", {"url": "/about"})], collector)
    assert len(collector.findings) == 1
    assert collector.findings[0].parameter == "url"
    assert collector.findings[0].severity == "Medium"
    assert "Location" in collector.findings[0].evidence


def test_safe_redirect_not_reported(handler, lab_url):
    collector = FindingsCollector()
    scan_redirects(handler, [point(lab_url, "/safe-goto", {"next": "/about"}),
                             point(lab_url, "/search", {"q": "laptop"})], collector)
    assert collector.findings == []

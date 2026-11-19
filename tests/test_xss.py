"""Tests for the reflected XSS scanner against the local test lab."""

from scanner.analysis.findings_collector import FindingsCollector
from scanner.crawler.crawler import InjectionPoint
from scanner.vulnerabilities.xss_scanner import (
    check_attribute_injection, check_tag_injection, scan_xss,
)


def point(lab_url, path, params, method="GET"):
    return InjectionPoint(method, lab_url + path, params, "url", lab_url + path)


def test_tag_check_on_html():
    assert check_tag_injection("<p>wvs123456x <wvs123456x></p>", "wvs123456")[0] == "High"
    # Encoded output is safe and must NOT be reported
    assert check_tag_injection("<p>&lt;wvs123456x&gt;</p>", "wvs123456") is None


def test_attribute_check():
    html = '<input value="wvs123456" wvs123456a="1">'
    assert check_attribute_injection(html, "wvs123456")[0] == "High"
    assert check_attribute_injection('<input value="wvs123456&quot; wvs123456a=&quot;1">', "wvs123456") is None


def test_detects_reflected_xss(handler, lab_url):
    collector = FindingsCollector()
    scan_xss(handler, [point(lab_url, "/search", {"q": "laptop"})], collector)
    assert len(collector.findings) == 1
    finding = collector.findings[0]
    assert finding.parameter == "q"
    assert finding.confidence == "High"
    assert finding.severity == "High"
    assert "Request:" in finding.evidence


def test_detects_attribute_xss(handler, lab_url):
    collector = FindingsCollector()
    scan_xss(handler, [point(lab_url, "/profile", {"name": "guest"})], collector)
    assert [f.parameter for f in collector.findings] == ["name"]


def test_no_false_positive_on_escaped_page(handler, lab_url):
    collector = FindingsCollector()
    scan_xss(handler, [point(lab_url, "/safe-search", {"q": "laptop"}),
                       point(lab_url, "/contact", {"email": "", "message": "", "topic": "general"}, "POST")],
             collector)
    assert collector.findings == []

"""Tests for the security header analyzer (uses fake responses, no network)."""

from requests.structures import CaseInsensitiveDict

from scanner.vulnerabilities.header_analyzer import analyze_headers


class FakeResponse:
    def __init__(self, headers):
        self.headers = CaseInsensitiveDict(headers)


GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Server": "nginx",
}


def names(findings):
    return {f.parameter: f for f in findings}


def test_secure_https_site_has_no_findings():
    assert analyze_headers(FakeResponse(GOOD_HEADERS), "https://site.test/") == []


def test_all_missing_headers_reported():
    found = names(analyze_headers(FakeResponse({}), "https://site.test/"))
    assert set(found) == {"Content-Security-Policy", "X-Frame-Options",
                          "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy"}
    assert found["X-Frame-Options"].severity == ""  # severity is set later by the collector


def test_weak_values_reported():
    headers = dict(GOOD_HEADERS)
    headers["Content-Security-Policy"] = "script-src 'self' 'unsafe-inline' *"
    headers["Strict-Transport-Security"] = "max-age=60"
    headers["X-Frame-Options"] = "ALLOW-FROM https://x.test"
    headers["Referrer-Policy"] = "unsafe-url"
    headers["X-Powered-By"] = "PHP/7.4.3"
    found = names(analyze_headers(FakeResponse(headers), "https://site.test/"))
    assert "unsafe-inline" in found["Content-Security-Policy"].description
    assert found["Strict-Transport-Security"].vuln_type == "weak_header"
    assert found["X-Frame-Options"].vuln_type == "weak_header"
    assert found["Referrer-Policy"].name == "Unsafe Referrer-Policy"
    assert found["X-Powered-By"].vuln_type == "info_disclosure"


def test_csp_with_nonce_is_fine():
    headers = dict(GOOD_HEADERS)
    headers["Content-Security-Policy"] = "script-src 'self' 'nonce-abc' 'unsafe-inline'; frame-ancestors 'none'"
    assert analyze_headers(FakeResponse(headers), "https://site.test/") == []


def test_http_site_reports_no_https():
    found = names(analyze_headers(FakeResponse(GOOD_HEADERS), "http://site.test/"))
    assert found["Strict-Transport-Security"].vuln_type == "no_https"


def test_lab_headers(handler, lab_url):
    response = handler.get(lab_url + "/")
    found = names(analyze_headers(response, lab_url + "/"))
    assert "Content-Security-Policy" in found and "X-Frame-Options" in found

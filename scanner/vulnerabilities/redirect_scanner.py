"""
Open Redirect Scanner.

An open redirect is a page like /goto?url=... that sends the visitor to ANY
address given in the parameter. Attackers use it for phishing:
    https://trusted-bank.com/goto?url=https://evil-site.com
looks safe because it starts with the real bank's domain.

How we test:
  * Only parameters with typical redirect names (url, next, redirect ...) or
    values that look like a URL/path are tested.
  * We put a controlled external address in the parameter:
        https://example.com/wvs-redirect-check
    example.com is reserved for documentation and testing (RFC 2606).
  * We do NOT follow the redirect. We only read the Location header (and
    <meta http-equiv="refresh"> tags) to see where the site would send us.
"""

import logging
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from scanner.analysis.findings_collector import Finding
from scanner.engine.request_handler import RequestLimitReached

logger = logging.getLogger(__name__)

TEST_DOMAIN = "example.com"
PAYLOADS = [
    f"https://{TEST_DOMAIN}/wvs-redirect-check",
    f"//{TEST_DOMAIN}/wvs-redirect-check",           # "protocol relative" URL
]

REDIRECT_PARAM_NAMES = {
    "url", "next", "redirect", "redirect_url", "redirect_uri", "redirecturl",
    "return", "return_to", "returnto", "returnurl", "return_url", "goto", "go",
    "dest", "destination", "continue", "target", "redir", "forward", "out",
    "to", "link", "location", "callback", "r", "u", "view", "page_url",
}

DESCRIPTION = (
    "This parameter controls where the website redirects the visitor, and it "
    "accepts addresses on other websites. Attackers can send links that start "
    "with your trusted domain but end on a phishing site."
)
REMEDIATION = (
    "Only redirect to relative paths on your own site, or check the target "
    "against an allowlist of trusted domains. Reject values that start with "
    "'http', '//' or contain a different host name."
)


def looks_like_redirect_param(name, value):
    if name.lower() in REDIRECT_PARAM_NAMES:
        return True
    value = (value or "").lower()
    return value.startswith(("http://", "https://", "/"))


def points_to_test_domain(location, request_url):
    full_url = urljoin(request_url, location)
    host = (urlparse(full_url).hostname or "").lower()
    return host == TEST_DOMAIN or host.endswith("." + TEST_DOMAIN)


def find_meta_refresh(response):
    """Return the URL from <meta http-equiv="refresh" content="0;url=..."> if any."""
    if "html" not in response.headers.get("Content-Type", "").lower():
        return None
    soup = BeautifulSoup(response.text, "html.parser")
    for meta in soup.find_all("meta"):
        if (meta.get("http-equiv") or "").lower() == "refresh":
            match = re.search(r"url\s*=\s*['\"]?([^'\";]+)", meta.get("content", ""), re.I)
            if match:
                return match.group(1).strip()
    return None


def scan_redirects(handler, injection_points, collector):
    for point in injection_points:
        for param in point.testable_params():
            if not looks_like_redirect_param(param, point.params.get(param)):
                continue
            try:
                check_parameter(handler, point, param, collector)
            except RequestLimitReached:
                raise
            except Exception as error:
                logger.warning("Redirect test failed for %s %s: %s", point.url, param, error)


def check_parameter(handler, point, param, collector):
    for payload in PAYLOADS:
        response = handler.send_payload(point, param, payload)
        if response is None:
            continue

        location = response.headers.get("Location") if response.is_redirect else None
        method_used = f"HTTP {response.status_code} redirect, Location: {location}"
        confidence = "High"
        if not location:
            location = find_meta_refresh(response)
            method_used = f"HTML meta refresh to: {location}"
            confidence = "Medium"

        if location and points_to_test_domain(location, point.url):
            collector.add(Finding(
                name="Open Redirect",
                vuln_type="open_redirect",
                url=point.url, parameter=param, confidence=confidence,
                description=DESCRIPTION,
                evidence=f"Request: {point.method} {point.url}  {param}={payload}\n"
                         f"Result: {method_used}",
                remediation=REMEDIATION,
            ))
            return

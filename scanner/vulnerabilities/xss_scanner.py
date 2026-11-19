"""
XSS Scanner - looks for reflected Cross-Site Scripting.

Reflected XSS happens when a website takes your input (for example ?q=hello)
and puts it straight back into the page without making it safe. An attacker
can then send a victim a link that runs JavaScript in the victim's browser.

How we test (without running any real attack code):
  1. Make a random marker, e.g. "wvsk3j9qz".
  2. Send a HARMLESS payload that tries to create a made-up HTML tag:
         wvsk3j9qz"'><wvsk3j9qzx>
     The tag <wvsk3j9qzx> does nothing at all, even if it gets through.
  3. Parse the response with BeautifulSoup:
     - If the made-up tag shows up as a REAL tag, the page lets us inject
       HTML. That means real JavaScript could be injected too. -> High confidence
     - If the payload shows up unchanged inside a <script> block -> Medium
     - If it is only printed back as text, or turned into &lt; &gt;, the site
       escaped it properly -> no finding (this avoids false positives).
  4. A second payload checks for breaking out of an attribute with a quote:
         wvsk3j9qz" wvsk3j9qza="1
"""

import logging
import secrets
import string

from bs4 import BeautifulSoup

from scanner.analysis.findings_collector import Finding, short_snippet
from scanner.engine.request_handler import RequestLimitReached

logger = logging.getLogger(__name__)

DESCRIPTION = (
    "The value of this parameter is written back into the HTML page without "
    "proper encoding. An attacker could craft a link that runs their own "
    "JavaScript in a victim's browser, for example to steal session cookies "
    "or change what the page shows."
)
REMEDIATION = (
    "Encode all user input before putting it into HTML (for example with "
    "html.escape() in Python, or the auto-escaping of Jinja2/Django templates). "
    "Validate input against an allowlist and add a Content-Security-Policy "
    "header as an extra layer of protection."
)


def make_marker():
    """Random lowercase marker so every test can be recognised exactly."""
    letters = string.ascii_lowercase + string.digits
    return "wvs" + "".join(secrets.choice(letters) for _ in range(6))


def is_html(response):
    return "html" in response.headers.get("Content-Type", "").lower()


def check_tag_injection(response_text, marker):
    """Return (confidence, reason) or None, for the made-up tag payload."""
    tag_name = marker + "x"
    soup = BeautifulSoup(response_text, "html.parser")

    if soup.find(tag_name) is not None:
        return "High", f"The made-up tag <{tag_name}> was parsed as a real HTML element."

    raw_tag = f"<{tag_name}>"
    for script in soup.find_all("script"):
        if raw_tag in (script.string or ""):
            return "Medium", "The payload was reflected unencoded inside a <script> block."
    return None


def check_attribute_injection(response_text, marker):
    attribute_name = marker + "a"
    soup = BeautifulSoup(response_text, "html.parser")
    if soup.find(attrs={attribute_name: True}) is not None:
        return "High", f"A new attribute '{attribute_name}' was created by breaking out of a quoted value."
    return None


def scan_xss(handler, injection_points, collector):
    """Test every parameter of every injection point for reflected XSS."""
    for point in injection_points:
        for param in point.testable_params():
            try:
                check_parameter(handler, point, param, collector)
            except RequestLimitReached:
                raise
            except Exception as error:  # one broken page must not stop the whole scan
                logger.warning("XSS test failed for %s %s: %s", point.url, param, error)


def check_parameter(handler, point, param, collector):
    marker = make_marker()
    tests = [
        (f"{marker}\"'><{marker}x>", check_tag_injection),
        (f'{marker}" {marker}a="1', check_attribute_injection),
    ]
    for payload, checker in tests:
        response = handler.send_payload(point, param, payload)
        if response is None or not is_html(response):
            continue
        if marker not in response.text:
            continue  # the input is not reflected at all

        result = checker(response.text, marker)
        if result:
            confidence, reason = result
            evidence = (
                f"Request: {point.method} {point.url}  {param}={payload}\n"
                f"Result: {reason}\n"
                f"Response snippet: {short_snippet(response.text, marker)}"
            )
            collector.add(Finding(
                name="Reflected Cross-Site Scripting (XSS)",
                vuln_type="reflected_xss",
                url=point.url,
                parameter=param,
                confidence=confidence,
                description=DESCRIPTION,
                evidence=evidence,
                remediation=REMEDIATION,
            ))
            return  # one finding per parameter is enough

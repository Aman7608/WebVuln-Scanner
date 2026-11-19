"""
Stored XSS Scanner.

Stored (or "persistent") XSS is worse than reflected XSS: the input is SAVED
by the website (a comment, a guestbook entry, a profile name) and shown to
EVERY visitor who opens the page later - nobody has to click a special link.

How we test:
  1. Submit every form once, putting a different harmless marker tag in each
     field, e.g.  wvsab12cd"'><wvsab12cdx>
     (the made-up tag does nothing even if it is shown).
  2. After ALL forms are submitted, load the crawled pages again with normal
     GET requests (no test input at all).
  3. If one of our markers now appears on a page as a REAL HTML tag, the
     site stored our input and shows it without encoding -> stored XSS.

Because step 1 really saves data on the website (for example a new
guestbook entry), this module is OFF by default. Only run it on test sites.
"""

import logging

from bs4 import BeautifulSoup

from scanner.analysis.findings_collector import Finding, short_snippet
from scanner.engine.request_handler import RequestLimitReached
from scanner.vulnerabilities.xss_scanner import make_marker

logger = logging.getLogger(__name__)

MAX_PAGES_TO_RECHECK = 50

DESCRIPTION = (
    "Input sent through this form is saved by the website and later shown on a "
    "page without proper encoding. Any JavaScript an attacker saves here would "
    "run in the browser of EVERY user who views that page, without them clicking "
    "a special link."
)
REMEDIATION = (
    "Encode saved data every time it is written into HTML (template auto-escaping, "
    "html.escape()). If users may enter formatted text, clean it with an HTML "
    "sanitizer that only allows safe tags. Add a Content-Security-Policy as an "
    "extra layer of protection."
)


def submit_markers(handler, injection_points):
    """Step 1: put a unique marker in every form field. Returns {marker: (point, param)}."""
    planted = {}
    for point in injection_points:
        if point.source != "form":
            continue  # stored data almost always comes from forms
        for param in point.testable_params():
            marker = make_marker()
            payload = f"{marker}\"'><{marker}x>"
            try:
                handler.send_payload(point, param, payload)
            except RequestLimitReached:
                raise
            except Exception as error:
                logger.warning("Stored XSS submit failed for %s %s: %s", point.url, param, error)
                continue
            planted[marker] = (point, param)
    return planted


def scan_stored_xss(handler, injection_points, page_urls, collector):
    planted = submit_markers(handler, injection_points)
    if not planted:
        return

    # Step 2: re-visit the pages (crawled pages + pages where the forms were found)
    pages = list(dict.fromkeys(page_urls + [p.page_url for p, _ in planted.values()]))
    for page_url in pages[:MAX_PAGES_TO_RECHECK]:
        response = handler.get(page_url)
        if response is None or "html" not in response.headers.get("Content-Type", "").lower():
            continue
        if not any(marker in response.text for marker in planted):
            continue

        # Step 3: is any marker now a REAL tag on this page?
        soup = BeautifulSoup(response.text, "html.parser")
        for marker, (point, param) in planted.items():
            if soup.find(marker + "x") is None:
                continue
            collector.add(Finding(
                name="Stored Cross-Site Scripting (XSS)",
                vuln_type="stored_xss",
                url=point.url,
                parameter=param,
                confidence="High",
                description=DESCRIPTION,
                evidence=(
                    f"Submitted: {point.method} {point.url}  {param}={marker}\"'><{marker}x>\n"
                    f"Later found as a real HTML tag on: {page_url}\n"
                    f"Page snippet: {short_snippet(response.text, marker)}"
                ),
                remediation=REMEDIATION,
            ))

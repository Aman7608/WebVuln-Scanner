"""
Security Header Analyzer.

HTTP security headers are instructions the server sends to the browser to
turn on extra protections. This is a "passive" check: we only READ the
headers of a normal response, we do not send any test input.

Headers checked:
  Content-Security-Policy    limits where scripts can load from (stops many XSS)
  X-Frame-Options            stops other sites showing the page in a frame (clickjacking)
  Strict-Transport-Security  forces the browser to always use HTTPS
  X-Content-Type-Options     stops the browser guessing file types ("nosniff")
  Referrer-Policy            controls how much of the URL is shared with other sites
Plus: Server / X-Powered-By headers that reveal software versions.
"""

import re
from urllib.parse import urlparse

from scanner.analysis.findings_collector import Finding

MIN_HSTS_MAX_AGE = 15552000  # 180 days, a common minimum recommendation


def make_finding(name, vuln_type, url, header, confidence, description, evidence, remediation):
    return Finding(name=name, vuln_type=vuln_type, url=url, parameter=header,
                   confidence=confidence, description=description,
                   evidence=evidence, remediation=remediation)


def check_csp(headers, url):
    csp = headers.get("Content-Security-Policy")
    if not csp:
        return [make_finding(
            "Missing Content-Security-Policy header", "missing_csp", url,
            "Content-Security-Policy", "High",
            "The page has no Content-Security-Policy. CSP tells the browser which "
            "scripts are allowed to run, which makes XSS attacks much harder.",
            "Header 'Content-Security-Policy' is not present in the response.",
            "Add a policy such as: Content-Security-Policy: default-src 'self'; "
            "object-src 'none'; frame-ancestors 'self'. Start strict and relax it only where needed.",
        )]

    problems = []
    # Look at the directive that controls scripts (script-src, or default-src as fallback)
    directives = {part.strip().split(" ")[0].lower(): part.strip()
                  for part in csp.split(";") if part.strip()}
    script_rule = directives.get("script-src") or directives.get("default-src") or ""
    uses_nonce_or_hash = "'nonce-" in script_rule or "'sha256-" in script_rule
    if "'unsafe-inline'" in script_rule and not uses_nonce_or_hash:
        problems.append("allows 'unsafe-inline' scripts")
    if "'unsafe-eval'" in script_rule:
        problems.append("allows 'unsafe-eval'")
    if re.search(r"(^|\s)\*(\s|$)", script_rule):
        problems.append("allows scripts from any domain (*)")
    if not script_rule:
        problems.append("has no script-src or default-src directive")

    if problems:
        return [make_finding(
            "Weak Content-Security-Policy", "weak_header", url,
            "Content-Security-Policy", "Medium",
            "A CSP is present but it " + ", ".join(problems) + ", which removes much of its protection.",
            f"Content-Security-Policy: {csp}",
            "Remove 'unsafe-inline', 'unsafe-eval' and wildcard (*) sources. Use nonces or "
            "hashes for the few inline scripts you really need.",
        )]
    return []


def check_frame_options(headers, url):
    value = headers.get("X-Frame-Options", "").strip().upper()
    csp = headers.get("Content-Security-Policy", "").lower()
    if "frame-ancestors" in csp:
        return []  # CSP frame-ancestors is the modern replacement, so this is fine
    if not value:
        return [make_finding(
            "Missing X-Frame-Options header", "missing_xfo", url, "X-Frame-Options", "High",
            "Other websites can load this page inside an invisible frame and trick "
            "users into clicking buttons (clickjacking).",
            "Neither 'X-Frame-Options' nor CSP 'frame-ancestors' is present.",
            "Add X-Frame-Options: DENY (or SAMEORIGIN), or the CSP directive "
            "frame-ancestors 'self'.",
        )]
    if value not in ("DENY", "SAMEORIGIN"):
        return [make_finding(
            "Weak X-Frame-Options value", "weak_header", url, "X-Frame-Options", "Medium",
            f"X-Frame-Options is set to '{value}', which modern browsers do not support.",
            f"X-Frame-Options: {value}",
            "Use X-Frame-Options: DENY or SAMEORIGIN, or CSP frame-ancestors.",
        )]
    return []


def check_hsts(headers, url):
    if urlparse(url).scheme != "https":
        # HSTS only works over HTTPS, so we report the missing HTTPS instead
        return [make_finding(
            "Page served over plain HTTP", "no_https", url, "Strict-Transport-Security", "High",
            "The page is loaded without HTTPS, so anyone on the same network can read "
            "or change the traffic. (Local test servers often use HTTP; real sites must not.)",
            f"The target URL uses http:// ({url}).",
            "Serve the site only over HTTPS, redirect HTTP to HTTPS, then add "
            "Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        )]
    value = headers.get("Strict-Transport-Security")
    if not value:
        return [make_finding(
            "Missing Strict-Transport-Security header", "missing_hsts", url,
            "Strict-Transport-Security", "High",
            "Without HSTS a user's first visit can be downgraded to unencrypted HTTP "
            "by an attacker on the network.",
            "Header 'Strict-Transport-Security' is not present.",
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        )]
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    max_age = int(match.group(1)) if match else 0
    if max_age < MIN_HSTS_MAX_AGE:
        return [make_finding(
            "Weak Strict-Transport-Security max-age", "weak_header", url,
            "Strict-Transport-Security", "Medium",
            f"HSTS max-age is only {max_age} seconds, so the protection expires quickly.",
            f"Strict-Transport-Security: {value}",
            "Use max-age of at least 15552000 (180 days); 31536000 (1 year) is common.",
        )]
    return []


def check_content_type_options(headers, url):
    value = headers.get("X-Content-Type-Options", "").strip().lower()
    if value == "nosniff":
        return []
    return [make_finding(
        "Missing X-Content-Type-Options header" if not value else "Wrong X-Content-Type-Options value",
        "missing_xcto", url, "X-Content-Type-Options", "High",
        "Without 'nosniff' the browser may guess a file's type, so an uploaded text "
        "file could be run as a script.",
        f"X-Content-Type-Options: {value or '(not present)'}",
        "Add X-Content-Type-Options: nosniff.",
    )]


def check_referrer_policy(headers, url):
    value = headers.get("Referrer-Policy", "").strip().lower()
    unsafe_values = {"unsafe-url", "no-referrer-when-downgrade"}
    if value and not (set(v.strip() for v in value.split(",")) & unsafe_values):
        return []
    return [make_finding(
        "Missing Referrer-Policy header" if not value else "Unsafe Referrer-Policy",
        "missing_referrer", url, "Referrer-Policy", "High" if not value else "Medium",
        "When users click a link to another site, the full URL of this page (which "
        "can contain IDs or tokens) may be sent to that site.",
        f"Referrer-Policy: {value or '(not present)'}",
        "Add Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
    )]


def check_version_disclosure(headers, url):
    findings = []
    for header in ("Server", "X-Powered-By"):
        value = headers.get(header, "")
        if re.search(r"\d", value):  # a version number like Apache/2.4.1
            findings.append(make_finding(
                f"Software version shown in {header} header", "info_disclosure", url,
                header, "High",
                "The server tells everyone which software and version it runs. "
                "Attackers use this to look up known vulnerabilities.",
                f"{header}: {value}",
                f"Remove the version from the {header} header in the web server settings.",
            ))
    return findings


def analyze_headers(response, url):
    """Check one HTTP response and return a list of Findings."""
    headers = response.headers  # requests' headers are case-insensitive
    findings = []
    for check in (check_csp, check_frame_options, check_hsts,
                  check_content_type_options, check_referrer_policy,
                  check_version_disclosure):
        findings.extend(check(headers, url))
    return findings


def scan_headers(handler, url, collector):
    response = handler.get(url)
    if response is None:
        return
    for finding in analyze_headers(response, url):
        collector.add(finding)

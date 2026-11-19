"""
Directory Discovery - checks a SHORT list of common paths.

Websites sometimes leave files online by mistake: a .env file with
passwords, a .git folder with the source code, a backup, or an admin page.
We check about 30 well-known paths (not thousands - this is not a brute-force
tool) and record the HTTP status code of each one.

Avoiding false positives:
  * Some sites return "200 OK" for EVERY address, even ones that do not exist
    (a "soft 404"). First we request a random path that cannot exist and
    remember that page. Any result that looks the same is ignored.
  * For sensitive files we also check the CONTENT, e.g. a real .git/HEAD
    file starts with "ref:".
"""

import difflib
import logging
import re
import secrets
from urllib.parse import urljoin

from scanner.analysis.findings_collector import Finding
from scanner.engine.request_handler import RequestLimitReached

logger = logging.getLogger(__name__)


def content_has(pattern):
    """Make a small function that checks a response body with a regex."""
    return lambda text: re.search(pattern, text, re.I | re.M) is not None


# (path, vulnerability type, short description, optional content check)
COMMON_PATHS = [
    ("/.env", "sensitive_file", "Environment file that often holds passwords and API keys",
     content_has(r"^[A-Z0-9_]+\s*=")),
    ("/.git/HEAD", "sensitive_file", "Git repository - the source code can be downloaded",
     content_has(r"^(ref:|[0-9a-f]{40})")),
    ("/.git/config", "sensitive_file", "Git configuration file", content_has(r"\[core\]")),
    ("/config.php.bak", "sensitive_file", "Backup of a PHP configuration file", content_has(r"<\?php|define\(")),
    ("/wp-config.php.bak", "sensitive_file", "Backup of the WordPress configuration", content_has(r"DB_PASSWORD")),
    ("/backup.sql", "sensitive_file", "Database backup", content_has(r"CREATE TABLE|INSERT INTO")),
    ("/database.sql", "sensitive_file", "Database backup", content_has(r"CREATE TABLE|INSERT INTO")),
    ("/dump.sql", "sensitive_file", "Database dump", content_has(r"CREATE TABLE|INSERT INTO")),
    ("/.htpasswd", "sensitive_file", "Password file for Apache", content_has(r"^\w+:\S+")),
    ("/phpinfo.php", "exposed_resource", "PHP information page", content_has(r"PHP Version")),
    ("/server-status", "exposed_resource", "Apache server status page", content_has(r"Server Status")),
    ("/.DS_Store", "exposed_resource", "macOS folder index file that lists file names", None),
    ("/backup/", "exposed_resource", "Backup folder", None),
    ("/backups/", "exposed_resource", "Backup folder", None),
    ("/admin/", "exposed_resource", "Admin area", None),
    ("/administrator/", "exposed_resource", "Admin area", None),
    ("/phpmyadmin/", "exposed_resource", "phpMyAdmin database manager", None),
    ("/wp-admin/", "exposed_resource", "WordPress admin area", None),
    ("/uploads/", "exposed_resource", "Uploads folder", None),
    ("/test/", "exposed_resource", "Test folder", None),
    ("/debug/", "exposed_resource", "Debug page or folder", None),
    ("/console/", "exposed_resource", "Web console", None),
    ("/logs/", "exposed_resource", "Log files folder", None),
    ("/api/", "interesting_resource", "API root", None),
    ("/robots.txt", "interesting_resource", "robots.txt (can reveal hidden paths)",
     content_has(r"user-agent|disallow")),
    ("/sitemap.xml", "interesting_resource", "Sitemap listing the site's pages", content_has(r"<urlset|<sitemap")),
    ("/.well-known/security.txt", "interesting_resource", "Security contact file", content_has(r"contact:")),
    ("/crossdomain.xml", "interesting_resource", "Flash cross-domain policy", content_has(r"cross-domain-policy")),
]

REMEDIATION = {
    "sensitive_file": "Remove this file from the web server right away and change any passwords or "
                      "keys it contains. Block hidden files (starting with a dot) and backups in "
                      "the web server configuration.",
    "exposed_resource": "Remove the resource if it is not needed, or protect it with authentication "
                        "and IP restrictions. Turn off directory listing in the web server.",
    "interesting_resource": "No action needed in most cases. Make sure the file does not reveal "
                            "secret or internal paths.",
}


def redact_secrets(text):
    """Hide values like PASSWORD=abc123 -> PASSWORD=****, so reports never store real secrets."""
    text = re.sub(r"(?m)^([A-Za-z0-9_.\-]+\s*[=:]\s*)\S.*$", r"\1****", text)
    return re.sub(r"(define\(\s*'[^']+'\s*,\s*)'[^']*'", r"\1'****'", text)


def similar(text_a, text_b):
    return difflib.SequenceMatcher(None, text_a[:3000], text_b[:3000]).ratio() > 0.9


def scan_directories(handler, target_url, collector):
    """Check the common paths. Returns a list of {url, status_code} for every path."""
    checked = []

    # 1. Learn what a "not found" page looks like on this site
    random_path = f"/wvs-not-found-{secrets.token_hex(6)}"
    not_found = handler.get(urljoin(target_url, random_path))
    soft_404_text = not_found.text if (not_found is not None and not_found.status_code == 200) else None

    for path, vuln_type, description, content_check in COMMON_PATHS:
        url = urljoin(target_url, path)
        try:
            response = handler.get(url)
        except RequestLimitReached:
            logger.warning("Request limit reached during directory discovery")
            break
        if response is None:
            continue
        checked.append({"url": url, "status_code": response.status_code})

        if response.status_code in (401, 403):
            # The path exists but is protected - worth knowing, not a vulnerability
            collector.add(Finding(
                name=f"Protected resource found: {path}", vuln_type="interesting_resource",
                url=url, parameter="", confidence="Medium",
                description=f"{description}. It exists but access is denied (HTTP {response.status_code}).",
                evidence=f"GET {url} -> HTTP {response.status_code}",
                remediation=REMEDIATION["interesting_resource"],
            ))
            continue

        if response.status_code != 200:
            continue
        if soft_404_text is not None and similar(response.text, soft_404_text):
            continue  # looks like the site's normal "not found" page

        confidence = "Medium"
        if content_check is not None:
            if not content_check(response.text):
                continue  # 200 OK but not the expected content -> ignore
            confidence = "High"
        if "Index of /" in response.text:
            confidence = "High"
            description += " (directory listing is enabled)"

        collector.add(Finding(
            name=f"Exposed resource: {path}", vuln_type=vuln_type, url=url, parameter="",
            confidence=confidence,
            description=f"{description} is publicly accessible.",
            evidence=f"GET {url} -> HTTP 200, {len(response.content)} bytes\n"
                     f"Start of response (secrets hidden): {redact_secrets(response.text[:200])}",
            remediation=REMEDIATION[vuln_type],
        ))
    return checked

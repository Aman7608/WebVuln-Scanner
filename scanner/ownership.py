"""
Ownership verification - proves that a user really controls a website.

A checkbox saying "I am authorized" is not enough on a public service: anyone
could tick it and scan someone else's site. Professional scanners therefore
ask you to prove ownership first, and so do we. The user gets a random code
(token) and must publish it in ONE of two ways:

  1. File: put a text file at
         https://<site>/.well-known/webvuln-verify.txt
     containing only the code. Only someone who can upload files to the site
     can do this.

  2. DNS: add a TXT record named
         _webvuln-verify.<site>
     with the code as its value. Only someone who controls the domain's DNS
     can do this.

The check itself goes through the same SSRF protection as scans, so it cannot
be used to poke at internal addresses either.
"""

import logging
import re
import secrets

import requests

from config import settings
from scanner.engine.safe_connection import protect_session

logger = logging.getLogger(__name__)

VERIFY_FILE_PATH = "/.well-known/webvuln-verify.txt"
DNS_RECORD_PREFIX = "_webvuln-verify."

# A host name is letters, digits, dots and dashes (or an IP address)
HOST_PATTERN = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


class VerificationError(Exception):
    """Raised with a friendly message when ownership could not be proven."""


def new_token():
    return "webvuln-verify-" + secrets.token_hex(16)


def clean_host(text):
    """Turn "https://Example.com/page" or "example.com" into "example.com"."""
    text = (text or "").strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0]
    if text.count(":") == 1:          # remove a port like example.com:8080
        text = text.split(":", 1)[0]
    if not HOST_PATTERN.match(text):
        raise VerificationError("Please enter a valid domain name, for example example.com")
    return text


def verification_urls(host):
    """Where we look for the verification file (HTTPS first)."""
    return [f"https://{host}{VERIFY_FILE_PATH}", f"http://{host}{VERIFY_FILE_PATH}"]


def check_file(host, token):
    session = protect_session(requests.Session())
    session.headers["User-Agent"] = settings.USER_AGENT
    try:
        for url in verification_urls(host):
            try:
                response = session.get(url, timeout=10, allow_redirects=False)
            except requests.RequestException as error:
                logger.info("Verification file not reachable at %s: %s", url, error)
                continue
            if response.status_code == 200 and response.text[:500].strip() == token:
                return True
    finally:
        session.close()
    return False


def check_dns(host, token):
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return False
    try:
        answers = dns.resolver.resolve(DNS_RECORD_PREFIX + host, "TXT", lifetime=5)
    except (dns.exception.DNSException, ValueError):
        return False
    for answer in answers:
        text = b"".join(answer.strings).decode(errors="ignore").strip()
        if text == token:
            return True
    return False


def verify(host, token):
    """Return "file" or "dns" (the method that worked), or raise VerificationError."""
    if check_file(host, token):
        return "file"
    if check_dns(host, token):
        return "dns"
    raise VerificationError(
        f"Could not find the code. Make sure {VERIFY_FILE_PATH} on {host} contains exactly the "
        f"code, or that the DNS TXT record {DNS_RECORD_PREFIX}{host} has it (DNS changes can "
        "take a few minutes).")

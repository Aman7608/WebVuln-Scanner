"""
Target Manager - decides WHAT the scanner is allowed to scan.

Before any scan starts, the target URL goes through three checks:
  1. Is it a valid http:// or https:// URL?
  2. Is the host on the allowlist in config/settings.py?
  3. Does the host point to a private/internal address that is NOT allowlisted?

During the scan, every request is checked with is_in_scope() so the scanner
never wanders off to another website (for example by following a redirect).
"""

import ipaddress
import logging
import socket
from urllib.parse import urlparse

from config import settings

logger = logging.getLogger(__name__)

# These addresses are never allowed, even if someone adds them to the allowlist.
# 169.254.169.254 is the "cloud metadata" address used by AWS, Azure and GCP.
# Scanning it from a cloud server could leak secret keys.
ALWAYS_BLOCKED_IPS = {"169.254.169.254", "fd00:ec2::254"}


class TargetError(Exception):
    """Raised when a target URL is not valid or not allowed."""


def validate_url(url):
    """Check that the URL looks correct and clean it up a little.

    Returns the cleaned URL. Raises TargetError if something is wrong.
    """
    if not url or not isinstance(url, str):
        raise TargetError("Please enter a target URL.")

    url = url.strip()
    if " " in url:
        raise TargetError("The URL must not contain spaces.")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise TargetError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise TargetError("The URL has no host name (example: http://localhost:5001).")
    if parsed.username or parsed.password:
        raise TargetError("Please remove the username/password from the URL.")

    try:
        # Reading .port raises ValueError when the port is not a valid number
        _ = parsed.port
    except ValueError:
        raise TargetError("The port number in the URL is not valid.")

    # Add a "/" path if there is none, so http://site and http://site/ are the same
    path = parsed.path or "/"
    cleaned = parsed._replace(path=path, fragment="").geturl()
    return cleaned


def is_host_allowlisted(hostname):
    """Return True if this host is in the ALLOWED_HOSTS list."""
    return hostname.lower() in settings.ALLOWED_HOSTS


def resolve_host(hostname):
    """Look up all IP addresses for a host name. Returns a list of strings."""
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise TargetError(f"Could not find the host '{hostname}'. Check the spelling.")
    # Each result is a tuple; the IP address is in result[4][0]
    return sorted({result[4][0] for result in results})


def is_private_ip(ip_text):
    """Return True for loopback, private, link-local and other internal addresses."""
    ip = ipaddress.ip_address(ip_text.split("%")[0])  # remove IPv6 zone like %eth0
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def check_target(url):
    """Run all the checks on a target URL.

    Returns a dictionary with the cleaned URL, host and IP addresses.
    Raises TargetError with a friendly message if the target is not allowed.
    """
    cleaned_url = validate_url(url)
    hostname = urlparse(cleaned_url).hostname.lower()

    if not is_host_allowlisted(hostname):
        raise TargetError(
            f"'{hostname}' is not on the allowlist. Only scan websites you own or "
            "have written permission to test. Add the host to ALLOWED_HOSTS in "
            "config/settings.py (or the WEBVULN_ALLOWED_HOSTS variable)."
        )

    ip_addresses = resolve_host(hostname)
    for ip_text in ip_addresses:
        if ip_text in ALWAYS_BLOCKED_IPS:
            raise TargetError("Cloud metadata addresses can never be scanned.")

    # A host can be on the allowlist and still resolve to an internal address
    # (for example localhost -> 127.0.0.1). That is fine because the user
    # allowlisted it on purpose. The private IP check below protects against
    # an allowlisted *name* that unexpectedly points inside the network,
    # unless the IP itself is also allowlisted or the name is a local name.
    local_names = {"localhost"}
    for ip_text in ip_addresses:
        if is_private_ip(ip_text):
            if hostname in local_names or is_host_allowlisted(ip_text) or hostname == ip_text:
                continue
            raise TargetError(
                f"'{hostname}' points to the internal address {ip_text}. "
                f"Add {ip_text} to the allowlist too if this is really intended."
            )

    logger.info("Target accepted: %s (%s)", cleaned_url, ", ".join(ip_addresses))
    return {"url": cleaned_url, "host": hostname, "ip_addresses": ip_addresses}


def is_in_scope(url, target_url):
    """Return True if url is on the same scheme, host and port as the target.

    The scanner uses this before EVERY request, so it never leaves the target.
    """
    try:
        candidate = urlparse(url)
        target = urlparse(target_url)
        return (
            candidate.scheme in ("http", "https")
            and candidate.scheme == target.scheme
            and (candidate.hostname or "").lower() == (target.hostname or "").lower()
            and candidate.port == target.port
        )
    except ValueError:
        return False

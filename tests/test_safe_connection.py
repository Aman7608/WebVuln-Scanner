"""Tests for the SSRF protection that checks every connection."""

import socket

import pytest

from scanner import target_manager
from scanner.engine.request_handler import RequestHandler

REAL_GETADDRINFO = socket.getaddrinfo


def fake_dns(mapping):
    """Return a getaddrinfo that answers some names with chosen IPs (like a DNS attacker)."""
    def getaddrinfo(host, port, *args, **kwargs):
        if host in mapping:
            port = port or 80
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], int(port)))]
        return REAL_GETADDRINFO(host, port, *args, **kwargs)
    return getaddrinfo


def test_local_mode_lab_still_works(lab_url):
    handler = RequestHandler(lab_url, delay=0)
    assert handler.get(lab_url + "/").status_code == 200


def test_public_mode_blocks_loopback_at_connection_time(lab_url, monkeypatch):
    monkeypatch.setattr("config.settings.PUBLIC_MODE", True)
    handler = RequestHandler(lab_url, delay=0)
    assert handler.get(lab_url + "/") is None


def test_dns_rebinding_is_blocked(lab_url, monkeypatch):
    """A name that was fine during the check but now points to 127.0.0.1 is blocked."""
    port = lab_url.rsplit(":", 1)[1]
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"rebind.test": "127.0.0.1"}))
    target = f"http://rebind.test:{port}/"
    handler = RequestHandler(target, delay=0)
    assert handler.get(target) is None           # rebind.test is not allowlisted


def test_allowlisted_ip_is_reachable_but_metadata_never(monkeypatch):
    assert target_manager.is_connection_allowed("127.0.0.1", "127.0.0.1")
    monkeypatch.setattr("config.settings.ALLOWED_HOSTS", ["169.254.169.254", "127.0.0.1"])
    assert not target_manager.is_connection_allowed("169.254.169.254", "169.254.169.254")


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.10", "172.16.0.1", "127.0.0.1", "::1",
                                "169.254.10.10", "100.64.0.1", "0.0.0.0"])
def test_public_mode_blocks_every_internal_range(ip, monkeypatch):
    monkeypatch.setattr("config.settings.PUBLIC_MODE", True)
    assert not target_manager.is_connection_allowed("example.com", ip)


def test_public_mode_allows_internet_addresses(monkeypatch):
    monkeypatch.setattr("config.settings.PUBLIC_MODE", True)
    assert target_manager.is_connection_allowed("example.com", "93.184.215.14")


def test_proxy_settings_are_ignored(lab_url, monkeypatch):
    """A proxy would open the connection for us and skip the check, so proxies are ignored."""
    monkeypatch.setenv("HTTP_PROXY", "http://10.0.0.1:3128")
    handler = RequestHandler(lab_url, delay=0)
    assert handler.session.trust_env is False
    assert handler.get(lab_url + "/").status_code == 200

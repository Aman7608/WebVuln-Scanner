"""Tests for URL validation, the allowlist and scope checks."""

import pytest

from config import settings
from scanner import target_manager
from scanner.engine.request_handler import RequestHandler, RequestLimitReached
from scanner.target_manager import TargetError, check_target, is_in_scope, validate_url


@pytest.mark.parametrize("url", [
    "http://localhost:5001",
    "https://localhost/",
    "http://127.0.0.1:8080/login?next=/",
])
def test_valid_urls(url):
    assert validate_url(url).startswith(("http://", "https://"))


def test_validate_adds_slash_and_removes_fragment():
    assert validate_url("http://localhost:5001#top") == "http://localhost:5001/"


@pytest.mark.parametrize("url", [
    "", None, "localhost", "ftp://localhost/", "javascript:alert(1)",
    "http://", "http://local host/", "http://user:pass@localhost/",
    "http://localhost:99999/",
])
def test_invalid_urls(url):
    with pytest.raises(TargetError):
        validate_url(url)


def test_allowlisted_localhost_is_accepted():
    result = check_target("http://127.0.0.1:5001/")
    assert result["host"] == "127.0.0.1"


def test_host_not_on_allowlist_is_rejected():
    with pytest.raises(TargetError, match="not on the allowlist"):
        check_target("https://example.com/")


def test_metadata_ip_always_blocked(monkeypatch):
    monkeypatch.setattr(settings, "ALLOWED_HOSTS", ["169.254.169.254"])
    with pytest.raises(TargetError, match="metadata"):
        check_target("http://169.254.169.254/latest/meta-data/")


def test_allowlisted_name_pointing_to_private_ip_is_blocked(monkeypatch):
    # Pretend "intranet.test" is allowlisted but secretly resolves to 10.0.0.5
    monkeypatch.setattr(settings, "ALLOWED_HOSTS", ["intranet.test"])
    monkeypatch.setattr(target_manager, "resolve_host", lambda host: ["10.0.0.5"])
    with pytest.raises(TargetError, match="internal address"):
        check_target("http://intranet.test/")


def test_private_ip_allowed_when_ip_also_allowlisted(monkeypatch):
    monkeypatch.setattr(settings, "ALLOWED_HOSTS", ["intranet.test", "10.0.0.5"])
    monkeypatch.setattr(target_manager, "resolve_host", lambda host: ["10.0.0.5"])
    assert check_target("http://intranet.test/")["host"] == "intranet.test"


def test_scope_check():
    target = "http://127.0.0.1:5001/"
    assert is_in_scope("http://127.0.0.1:5001/search?q=1", target)
    assert not is_in_scope("http://127.0.0.1:5002/", target)       # other port
    assert not is_in_scope("https://127.0.0.1:5001/", target)      # other scheme
    assert not is_in_scope("http://example.com/", target)          # other host
    assert not is_in_scope("javascript:alert(1)", target)


def test_request_handler_blocks_out_of_scope(lab_url):
    handler = RequestHandler(lab_url, delay=0)
    assert handler.get("http://example.com/") is None
    assert handler.request_count == 0


def test_request_handler_limit(lab_url):
    handler = RequestHandler(lab_url, delay=0, max_requests=2)
    assert handler.get(lab_url + "/").status_code == 200
    handler.get(lab_url + "/about")
    with pytest.raises(RequestLimitReached):
        handler.get(lab_url + "/")


def test_request_handler_does_not_follow_redirects(lab_url):
    handler = RequestHandler(lab_url, delay=0)
    response = handler.get(lab_url + "/goto", params={"url": "https://example.com/"})
    assert response.status_code in (301, 302, 303, 307, 308)

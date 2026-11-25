"""Tests for proving website ownership (file and DNS) and the My websites pages."""

import pytest

from database import db
from scanner import ownership
from test_lab import vulnerable_app
from tests.conftest import csrf_from


@pytest.fixture
def lab_verification(monkeypatch, lab_url):
    """Point the file check at the lab (which runs on a random port) instead of port 80/443."""
    monkeypatch.setattr(ownership, "verification_urls",
                        lambda host: [lab_url + ownership.VERIFY_FILE_PATH])
    yield
    vulnerable_app.VERIFY_TOKEN["value"] = ""


@pytest.mark.parametrize("text, expected", [
    ("example.com", "example.com"),
    ("https://Example.COM/some/page?x=1", "example.com"),
    ("shop.example.com:8443", "shop.example.com"),
])
def test_clean_host(text, expected):
    assert ownership.clean_host(text) == expected


@pytest.mark.parametrize("text", ["", "not a host", "exa_mple.com", "-bad.com", "a" * 300])
def test_clean_host_rejects_bad_input(text):
    with pytest.raises(ownership.VerificationError):
        ownership.clean_host(text)


def test_tokens_are_random_and_long():
    first, second = ownership.new_token(), ownership.new_token()
    assert first != second and len(first) > 40


def test_file_verification(lab_verification):
    token = ownership.new_token()
    assert ownership.check_file("lab.test", token) is False        # file not there yet
    vulnerable_app.VERIFY_TOKEN["value"] = token
    assert ownership.verify("lab.test", token) == "file"
    assert ownership.check_file("lab.test", "webvuln-verify-wrong") is False


def test_dns_verification(monkeypatch):
    import dns.resolver

    class FakeAnswer:
        def __init__(self, text):
            self.strings = [text.encode()]

    def fake_resolve(name, record_type, lifetime):
        assert name == "_webvuln-verify.example.com" and record_type == "TXT"
        return [FakeAnswer("some-other-record"), FakeAnswer("webvuln-verify-abc")]

    monkeypatch.setattr(ownership, "check_file", lambda host, token: False)
    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
    assert ownership.verify("example.com", "webvuln-verify-abc") == "dns"
    with pytest.raises(ownership.VerificationError):
        ownership.verify("example.com", "webvuln-verify-xyz")


def test_verification_file_check_cannot_reach_internal_addresses(monkeypatch, lab_url):
    """In public mode the ownership check itself is protected against SSRF."""
    monkeypatch.setattr("config.settings.PUBLIC_MODE", True)
    monkeypatch.setattr(ownership, "verification_urls", lambda host: [lab_url + ownership.VERIFY_FILE_PATH])
    vulnerable_app.VERIFY_TOKEN["value"] = "webvuln-verify-x"
    try:
        assert ownership.check_file("lab.test", "webvuln-verify-x") is False
    finally:
        vulnerable_app.VERIFY_TOKEN["value"] = ""


def test_websites_page_flow(user_client, app, lab_verification):
    client = user_client
    client.post("/websites", data={"host": "https://my-lab.test/", "csrf_token": csrf_from(client)})
    path = app.config["DATABASE_PATH"]
    user = db.get_user_by_email(path, "alice@example.com")
    domain = db.list_domains(path, user["id"])[0]
    assert domain["host"] == "my-lab.test" and domain["verified_at"] is None

    page = client.get("/websites").data.decode()
    assert domain["token"] in page and "Not verified yet" in page

    # Wrong: the file is not published yet
    client.post(f"/websites/{domain['id']}/verify", data={"csrf_token": csrf_from(client)})
    assert not db.is_domain_verified(path, user["id"], "my-lab.test")

    vulnerable_app.VERIFY_TOKEN["value"] = domain["token"]
    client.post(f"/websites/{domain['id']}/verify", data={"csrf_token": csrf_from(client)})
    assert db.is_domain_verified(path, user["id"], "my-lab.test")
    assert "Verified (file)" in client.get("/websites").data.decode()


def test_cannot_verify_or_delete_someone_elses_domain(client, app):
    from tests.conftest import register
    path = app.config["DATABASE_PATH"]
    register(client, "alice@example.com")
    alice = db.get_user_by_email(path, "alice@example.com")
    domain_id = db.add_domain(path, alice["id"], "alice.test", "webvuln-verify-1")
    client.post("/logout", data={"csrf_token": csrf_from(client)})
    register(client, "bob@example.com")
    client.post(f"/websites/{domain_id}/delete", data={"csrf_token": csrf_from(client)})
    assert len(db.list_domains(path, alice["id"])) == 1

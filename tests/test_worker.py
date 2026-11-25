"""Tests for the scan queue, the worker, quotas and public mode rules."""

import pytest

from database import db
from scanner.engine import notify, worker
from scanner.engine.scan_engine import QuotaError, build_config, create_scan
from scanner.engine.secret_box import decrypt_secrets, encrypt_secrets
from scanner.target_manager import TargetError


def make_user(db_path, email="alice@example.com"):
    return db.create_user(db_path, email, "hash")


def test_queue_gives_each_scan_to_one_worker_in_order(db_path):
    target_id = db.get_or_create_target(db_path, "http://127.0.0.1/", "127.0.0.1")
    first = db.create_scan(db_path, target_id, {})
    second = db.create_scan(db_path, target_id, {})
    assert db.get_scan(db_path, first)["status"] == "queued"
    assert db.claim_next_scan(db_path) == first
    assert db.claim_next_scan(db_path) == second
    assert db.claim_next_scan(db_path) is None


def test_worker_runs_a_queued_scan(db_path, lab_url):
    config = build_config({"delay": 0, "modules": ["headers"]})
    scan_id, _ = create_scan(db_path, lab_url + "/", config)
    assert worker.run_one(db_path) == scan_id
    scan = db.get_scan(db_path, scan_id)
    assert scan["status"] == "completed" and scan["finding_count"] > 0
    assert worker.run_one(db_path) is None


def test_secrets_are_encrypted_in_the_queue_and_wiped(db_path, lab_url):
    from test_lab.vulnerable_app import LAB_PASSWORD
    form = {"delay": 0, "modules": ["headers"], "login_url": lab_url + "/account/login",
            "login_username": "tester"}
    scan_id, _ = create_scan(db_path, lab_url + "/", build_config(form),
                             secrets={"password": LAB_PASSWORD, "cookies": ""})
    with db.connect(db_path) as conn:
        stored = conn.execute("SELECT secrets_enc FROM scans WHERE id = ?", (scan_id,)).fetchone()["secrets_enc"]
    assert stored and LAB_PASSWORD not in stored
    assert decrypt_secrets(stored)["password"] == LAB_PASSWORD

    worker.run_one(db_path)
    assert db.get_scan(db_path, scan_id)["status"] == "completed"
    with db.connect(db_path) as conn:
        assert conn.execute("SELECT secrets_enc FROM scans WHERE id = ?", (scan_id,)).fetchone()["secrets_enc"] == ""


def test_secret_box_rejects_tampered_data():
    token = encrypt_secrets({"password": "pw", "cookies": ""})
    assert decrypt_secrets(token[:-4] + "AAAA") == {}
    assert encrypt_secrets({"password": "", "cookies": ""}) == ""


def test_cancel_queued_scan_never_runs(db_path):
    target_id = db.get_or_create_target(db_path, "http://127.0.0.1/", "127.0.0.1")
    scan_id = db.create_scan(db_path, target_id, {})
    assert db.request_cancel(db_path, scan_id)
    assert db.get_scan(db_path, scan_id)["status"] == "cancelled"
    assert db.claim_next_scan(db_path) is None


def test_housekeeping_deletes_old_scans_in_public_mode(db_path, monkeypatch):
    monkeypatch.setattr("config.settings.PUBLIC_MODE", True)
    monkeypatch.setattr("config.settings.RETENTION_DAYS", 30)
    target_id = db.get_or_create_target(db_path, "http://127.0.0.1/", "127.0.0.1")
    old = db.create_scan(db_path, target_id, {})
    new = db.create_scan(db_path, target_id, {})
    for scan_id in (old, new):
        db.finish_scan(db_path, scan_id, 0, 0)
    with db.connect(db_path) as conn:
        conn.execute("UPDATE scans SET started_at = ? WHERE id = ?", (db.time_ago(days=40), old))
    worker.housekeeping(db_path)
    assert db.get_scan(db_path, old) is None
    assert db.get_scan(db_path, new) is not None


def test_email_sent_when_user_wants_it(db_path, lab_url, monkeypatch):
    sent = []
    monkeypatch.setattr(notify, "send_scan_finished", lambda to, scan: sent.append((to, scan["status"])))
    user_id = make_user(db_path)
    db.set_email_notifications(db_path, user_id, True)
    create_scan(db_path, lab_url + "/", build_config({"delay": 0, "modules": ["headers"]}), user_id=user_id)
    worker.run_one(db_path)
    assert sent == [("alice@example.com", "completed")]


def test_email_message_content(monkeypatch):
    monkeypatch.setattr("config.settings.SMTP_FROM", "scanner@example.com")
    monkeypatch.setattr("config.settings.PUBLIC_BASE_URL", "https://scan.example.com")
    message = notify.build_message("alice@example.com", {
        "id": 7, "status": "completed", "target_url": "https://alice.test/", "finding_count": 3})
    assert message["To"] == "alice@example.com"
    assert "https://scan.example.com/scans/7" in message.get_content()


# ------------------------------------------------------------------ public mode
@pytest.fixture
def public_mode(monkeypatch):
    monkeypatch.setattr("config.settings.PUBLIC_MODE", True)


def test_public_mode_needs_verified_ownership(db_path, public_mode):
    user_id = make_user(db_path)
    # localhost is on the local allowlist, but the allowlist does not count in public mode
    with pytest.raises(TargetError, match="not verified"):
        create_scan(db_path, "http://127.0.0.1/", build_config({}), user_id=user_id)


def test_public_mode_blocks_internal_address_even_when_verified(db_path, public_mode):
    user_id = make_user(db_path)
    domain_id = db.add_domain(db_path, user_id, "127.0.0.1", "webvuln-verify-1")
    db.mark_domain_verified(db_path, domain_id, "file")
    with pytest.raises(TargetError, match="internal address"):
        create_scan(db_path, "http://127.0.0.1/", build_config({}), user_id=user_id)


def allow_lab_in_public_mode(monkeypatch, db_path, user_id):
    """Public-mode quota tests need a target. We verify the lab and let it through the
    internal-address rule ONLY inside these tests."""
    from scanner import target_manager
    domain_id = db.add_domain(db_path, user_id, "127.0.0.1", "webvuln-verify-1")
    db.mark_domain_verified(db_path, domain_id, "file")
    monkeypatch.setattr(target_manager, "is_connection_allowed", lambda host, ip: True)


def test_public_limits_are_applied(db_path, public_mode, monkeypatch, lab_url):
    user_id = make_user(db_path)
    allow_lab_in_public_mode(monkeypatch, db_path, user_id)
    config = build_config({"max_pages": 200, "max_requests": 3000, "delay": 0})
    scan_id, _ = create_scan(db_path, lab_url + "/", config, user_id=user_id)
    saved = db.get_scan(db_path, scan_id)["config"]
    assert saved["max_pages"] == 50 and saved["max_requests"] == 1000 and saved["delay"] == 0.2


def test_public_one_scan_at_a_time_and_daily_quota(db_path, public_mode, monkeypatch, lab_url):
    user_id = make_user(db_path)
    allow_lab_in_public_mode(monkeypatch, db_path, user_id)
    monkeypatch.setattr("config.settings.SCANS_PER_DAY", 2)

    first, _ = create_scan(db_path, lab_url + "/", build_config({}), user_id=user_id)
    with pytest.raises(QuotaError, match="already have a scan"):
        create_scan(db_path, lab_url + "/", build_config({}), user_id=user_id)

    db.request_cancel(db_path, first)                     # first one is done
    second, _ = create_scan(db_path, lab_url + "/", build_config({}), user_id=user_id)
    db.request_cancel(db_path, second)
    with pytest.raises(QuotaError, match="2 scans per"):
        create_scan(db_path, lab_url + "/", build_config({}), user_id=user_id)


def test_secret_key_required_in_public_mode(public_mode, monkeypatch):
    from config import secret_key
    monkeypatch.setattr("config.settings.SECRET_KEY", "")
    monkeypatch.setattr(secret_key, "_cached_key", None)
    with pytest.raises(RuntimeError, match="WEBVULN_SECRET_KEY"):
        secret_key.get_secret_key()


def test_public_mode_cookies_are_secure(public_mode, tmp_path):
    from app import create_app
    flask_app = create_app(database_path=str(tmp_path / "p.db"), start_worker=False)
    assert flask_app.config["SESSION_COOKIE_SECURE"] is True
    response = flask_app.test_client().get("/login")
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]

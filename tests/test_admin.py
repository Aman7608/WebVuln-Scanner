"""Tests for the admin area: block users, admin rights, password reset, all scans, settings, stats."""

import re

import pytest

from config import live_settings
from database import db
from tests.conftest import csrf_from, login, post_json, register

ADMIN = "admin@example.com"
BOB = "bob@example.com"
PASSWORD = "correct-horse-battery"


def logout(client):
    client.post("/logout", data={"csrf_token": csrf_from(client)})


def admin_post(client, url, data=None):
    return client.post(url, data={**(data or {}), "csrf_token": csrf_from(client)})


@pytest.fixture
def two_users(client, app):
    """admin@example.com (admin, logged in at the end) and bob@example.com (normal user)."""
    register(client, ADMIN)
    logout(client)
    register(client, BOB)
    logout(client)
    login(client, ADMIN)
    path = app.config["DATABASE_PATH"]
    return path, db.get_user_by_email(path, BOB)


@pytest.mark.parametrize("page", ["/admin", "/admin/users", "/admin/scans", "/admin/reports",
                                  "/admin/settings", "/admin/audit"])
def test_admin_pages_load_for_admin_only(two_users, client, page):
    assert client.get(page).status_code == 200
    logout(client)
    login(client, BOB)
    assert client.get(page).status_code == 403


def test_block_user_logs_them_out_and_stops_login(two_users, client, app):
    path, bob = two_users
    # Bob is logged in on another browser
    bob_browser = app.test_client()
    login(bob_browser, BOB)
    assert bob_browser.get("/").status_code == 200

    admin_post(client, f"/admin/users/{bob['id']}/block")
    assert db.get_user(path, bob["id"])["is_blocked"] == 1
    # Bob's open session ends at once
    assert bob_browser.get("/").status_code == 302
    # ...and he cannot log in again, even with the right password
    assert b"blocked" in login(bob_browser, BOB).data
    assert bob_browser.get("/").status_code == 302

    admin_post(client, f"/admin/users/{bob['id']}/block")          # unblock
    login(bob_browser, BOB)
    assert bob_browser.get("/").status_code == 200


def test_blocking_cancels_waiting_scans(two_users, client):
    path, bob = two_users
    target_id = db.get_or_create_target(path, "http://127.0.0.1:9/", "127.0.0.1")
    # Stop the worker from taking the scan, so it is still waiting when we block Bob
    scan_id = db.create_scan(path, target_id, {"modules": []}, user_id=bob["id"])
    with db.connect(path) as conn:
        conn.execute("UPDATE scans SET status = 'queued' WHERE id = ?", (scan_id,))
    admin_post(client, f"/admin/users/{bob['id']}/block")
    assert db.get_scan(path, scan_id)["status"] in ("cancelled", "completed", "failed")
    assert db.get_scan(path, scan_id)["status"] != "queued"


def test_make_and_remove_admin(two_users, client):
    path, bob = two_users
    admin_post(client, f"/admin/users/{bob['id']}/admin")
    assert db.get_user(path, bob["id"])["is_admin"] == 1
    admin_post(client, f"/admin/users/{bob['id']}/admin")
    assert db.get_user(path, bob["id"])["is_admin"] == 0


def test_admin_cannot_change_own_account(two_users, client):
    path, _ = two_users
    me = db.get_user_by_email(path, ADMIN)
    for action in ("block", "admin", "delete", "reset-password"):
        admin_post(client, f"/admin/users/{me['id']}/{action}")
    me_after = db.get_user_by_email(path, ADMIN)
    assert me_after["is_admin"] == 1 and me_after["is_blocked"] == 0
    assert me_after["password_hash"] == me["password_hash"]


def test_last_admin_cannot_be_removed(two_users, client, app):
    path, bob = two_users
    # Make Bob admin, then Bob tries to remove the original admin while being the 2nd admin: allowed.
    admin_post(client, f"/admin/users/{bob['id']}/admin")
    logout(client)
    login(client, BOB)
    me = db.get_user_by_email(path, ADMIN)
    admin_post(client, f"/admin/users/{me['id']}/admin")
    assert db.count_admins(path) == 1
    # Now Bob is the only admin. Nobody can demote, block or delete him (he can't do it to himself).
    assert db.get_user(path, bob["id"])["is_admin"] == 1


def test_password_reset_forces_new_password(two_users, client, app):
    path, bob = two_users
    page = admin_post(client, f"/admin/users/{bob['id']}/reset-password").data.decode()
    temporary = re.search(r'<code class="big-code">([^<]+)</code>', page).group(1)
    assert len(temporary) >= 12
    assert temporary not in db.get_user(path, bob["id"])["password_hash"]   # only the hash is stored

    bob_browser = app.test_client()
    assert b"Wrong email or password" in login(bob_browser, BOB, PASSWORD).data   # old password gone
    login(bob_browser, BOB, temporary)
    # Every page sends Bob to the Account page until he picks a new password
    response = bob_browser.get("/scan")
    assert response.status_code == 302 and response.headers["Location"].endswith("/account")
    assert post_json(bob_browser, "/api/scans", {"target_url": "http://127.0.0.1/"}).status_code == 403
    assert b"reset your password" in bob_browser.get("/account").data

    bob_browser.post("/account", data={"action": "password", "current_password": temporary,
                                       "new_password": "bobs-new-password-1",
                                       "csrf_token": csrf_from(bob_browser)})
    assert bob_browser.get("/scan").status_code == 200


def test_all_scans_page_shows_every_user(two_users, client):
    path, bob = two_users
    target_id = db.get_or_create_target(path, "http://bob-site.test/", "bob-site.test")
    scan_id = db.create_scan(path, target_id, {"modules": []}, user_id=bob["id"])
    db.request_cancel(path, scan_id)
    page = client.get("/admin/scans").data.decode()
    assert "bob-site.test" in page and BOB in page
    assert "bob-site.test" in client.get("/admin/scans?status=cancelled").data.decode()
    assert "bob-site.test" not in client.get("/admin/scans?status=completed").data.decode()


def test_settings_page_changes_limits_live(two_users, client, monkeypatch):
    path, _ = two_users
    admin_post(client, "/admin/settings", {"scans_per_day": "12", "max_running_scans_per_user": "2",
                                           "retention_days": "90"})   # registration box left unticked
    assert live_settings.get(path, "scans_per_day") == 12
    assert live_settings.get(path, "retention_days") == 90
    assert live_settings.get(path, "registration_open") is False
    # Sign-up is now closed for new people
    logout(client)
    assert register(client, "carol@example.com").status_code == 403
    # Values outside the allowed range are clamped
    login(client, ADMIN)
    admin_post(client, "/admin/settings", {"scans_per_day": "999999", "registration_open": "on",
                                           "max_running_scans_per_user": "1", "retention_days": "30"})
    assert live_settings.get(path, "scans_per_day") == 1000
    assert "Terms" in client.get("/terms").data.decode()


def test_settings_reject_text(two_users, client):
    response = admin_post(client, "/admin/settings", {"scans_per_day": "lots"})
    assert b"not a valid number" in response.data


def test_quota_uses_admin_setting(db_path, monkeypatch):
    from scanner.engine.scan_engine import QuotaError, check_quota
    monkeypatch.setattr("config.settings.PUBLIC_MODE", True)
    user_id = db.create_user(db_path, "x@example.com", "hash")
    db.save_setting(db_path, "scans_per_day", 1)
    target_id = db.get_or_create_target(db_path, "http://a.test/", "a.test")
    db.request_cancel(db_path, db.create_scan(db_path, target_id, {}, user_id=user_id))
    with pytest.raises(QuotaError, match="1 scans per"):
        check_quota(db_path, user_id)


def test_overview_numbers(two_users, client):
    page = client.get("/admin").data.decode()
    assert "Users" in page and "Open abuse reports" in page
    stats = db.service_stats(two_users[0])
    assert stats["users"] == 2 and stats["admins"] == 1


def test_audit_search(two_users, client):
    path, bob = two_users
    admin_post(client, f"/admin/users/{bob['id']}/block")
    page = client.get("/admin/audit?q=user_blocked").data.decode()
    assert "user blocked" in page and BOB in page
    assert "No events found" in client.get("/admin/audit?q=nothing-like-this").data.decode()


def test_old_database_gets_new_user_columns(tmp_path):
    import sqlite3
    path = str(tmp_path / "v2a.db")
    old = sqlite3.connect(path)
    old.executescript("""CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0,
        notify_by_email INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, last_login_at TEXT);
        INSERT INTO users (email, password_hash, created_at) VALUES ('old@example.com', 'h', '2026-11-25');""")
    old.close()
    db.init_db(path)
    user = db.get_user_by_email(path, "old@example.com")
    assert user["is_blocked"] == 0 and user["must_change_password"] == 0

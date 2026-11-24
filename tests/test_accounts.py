"""Tests for sign up, login, CSRF, per-user data and the admin area."""

from database import db
from tests.conftest import csrf_from, login, post_json, register


def logout(client):
    return client.post("/logout", data={"csrf_token": csrf_from(client)})


def test_first_user_becomes_admin_and_second_does_not(client, app):
    register(client, "admin@example.com")
    logout(client)
    register(client, "bob@example.com")
    path = app.config["DATABASE_PATH"]
    assert db.get_user_by_email(path, "admin@example.com")["is_admin"] == 1
    assert db.get_user_by_email(path, "bob@example.com")["is_admin"] == 0


def test_passwords_are_hashed(client, app):
    register(client, "alice@example.com", "correct-horse-battery")
    user = db.get_user_by_email(app.config["DATABASE_PATH"], "alice@example.com")
    assert "correct-horse-battery" not in user["password_hash"]
    assert user["password_hash"].startswith(("scrypt:", "pbkdf2:"))


def test_register_validation(client):
    client.get("/register")
    bad = [
        {"email": "not-an-email", "password": "long-enough-pw", "password_again": "long-enough-pw", "accept_terms": "on"},
        {"email": "a@example.com", "password": "short", "password_again": "short", "accept_terms": "on"},
        {"email": "a@example.com", "password": "long-enough-pw", "password_again": "different-pw!", "accept_terms": "on"},
        {"email": "a@example.com", "password": "long-enough-pw", "password_again": "long-enough-pw"},  # no terms
    ]
    for form in bad:
        response = client.post("/register", data={**form, "csrf_token": csrf_from(client)})
        assert response.status_code == 200 and b"alert-error" in response.data


def test_duplicate_email_refused(client):
    register(client, "alice@example.com")
    logout(client)
    response = register(client, "ALICE@example.com")
    assert b"already exists" in response.data


def test_login_and_logout(client):
    register(client)
    logout(client)
    assert client.get("/").status_code == 302
    assert login(client).status_code == 302
    assert client.get("/").status_code == 200


def test_wrong_password_gives_generic_message(client):
    register(client)
    logout(client)
    wrong_password = login(client, password="wrong-password-123").data
    unknown_user = login(client, email="nobody@example.com").data
    assert b"Wrong email or password" in wrong_password
    assert b"Wrong email or password" in unknown_user   # does not reveal which emails exist


def test_login_is_locked_after_many_failures(client, monkeypatch):
    monkeypatch.setattr("config.settings.LOGIN_MAX_FAILURES", 3)
    register(client)
    logout(client)
    for _ in range(3):
        login(client, password="wrong-password-123")
    # Even the right password is refused while locked
    response = login(client)
    assert b"Too many failed logins" in response.data
    assert client.get("/").status_code == 302


def test_post_without_csrf_token_is_refused(client):
    client.get("/register")
    response = client.post("/register", data={
        "email": "a@example.com", "password": "long-enough-pw", "password_again": "long-enough-pw",
        "accept_terms": "on"})
    assert response.status_code == 400


def test_login_redirect_cannot_leave_the_site(client):
    register(client)
    logout(client)
    response = client.post("/login?next=//evil.test/steal", data={
        "email": "alice@example.com", "password": "correct-horse-battery", "csrf_token": csrf_from(client)})
    assert response.headers["Location"] == "/"


def test_users_only_see_their_own_scans(client, app):
    path = app.config["DATABASE_PATH"]
    register(client, "alice@example.com")
    alice = db.get_user_by_email(path, "alice@example.com")
    target_id = db.get_or_create_target(path, "http://127.0.0.1/", "127.0.0.1")
    alice_scan = db.create_scan(path, target_id, {"modules": []}, user_id=alice["id"])
    db.request_cancel(path, alice_scan)
    logout(client)

    register(client, "bob@example.com")
    assert client.get(f"/scans/{alice_scan}").status_code == 404
    assert client.get(f"/api/scans/{alice_scan}").status_code == 404
    assert client.get(f"/scans/{alice_scan}/report.pdf").status_code == 404
    assert post_json(client, f"/api/scans/{alice_scan}/cancel").status_code == 404
    assert b"127.0.0.1" not in client.get("/history").data

    # The admin (alice, first user) can see every scan, e.g. for abuse reports
    logout(client)
    login(client, "alice@example.com")
    assert client.get(f"/scans/{alice_scan}").status_code == 200


def test_admin_page_only_for_admin(client):
    register(client, "admin@example.com")
    assert client.get("/admin").status_code == 200
    logout(client)
    register(client, "bob@example.com")
    assert client.get("/admin").status_code == 403


def test_registration_can_be_closed_but_first_admin_still_allowed(client, monkeypatch):
    monkeypatch.setattr("config.settings.REGISTRATION_OPEN", False)
    assert register(client, "admin@example.com").status_code == 302   # first account
    logout(client)
    assert register(client, "bob@example.com").status_code == 403


def test_change_password_and_delete_account(client, app):
    register(client)
    response = client.post("/account", data={
        "action": "password", "current_password": "correct-horse-battery",
        "new_password": "a-brand-new-password", "csrf_token": csrf_from(client)})
    assert b"Password changed" in response.data

    response = client.post("/account", data={
        "action": "delete_account", "confirm_password": "wrong", "csrf_token": csrf_from(client)})
    assert b"not deleted" in response.data

    client.post("/account", data={
        "action": "delete_account", "confirm_password": "a-brand-new-password",
        "csrf_token": csrf_from(client)})
    assert db.get_user_by_email(app.config["DATABASE_PATH"], "alice@example.com") is None
    assert client.get("/").status_code == 302


def test_audit_log_records_actions(client, app):
    register(client)
    logout(client)
    login(client, password="wrong-password-123")
    actions = [e["action"] for e in db.list_audit_log(app.config["DATABASE_PATH"])]
    assert {"account_created", "logout", "login_failed"} <= set(actions)


def test_abuse_report_reaches_admin(client):
    register(client, "admin@example.com")
    logout(client)
    client.get("/report-abuse")
    response = client.post("/report-abuse", data={
        "email": "owner@victim.test", "website": "victim.test", "message": "Many requests at 10:00",
        "csrf_token": csrf_from(client)})
    assert b"Thank you" in response.data
    login(client, "admin@example.com")
    page = client.get("/admin").data.decode()
    assert "victim.test" in page and "Many requests at 10:00" in page


def test_public_pages_work_without_login(client):
    assert client.get("/terms").status_code == 200
    assert client.get("/report-abuse").status_code == 200

"""
Account pages: sign up, log in, log out, and the "Account" page.

  * The first account ever created becomes the admin. In local mode it also
    takes over any scans made before accounts existed.
  * Login is slowed down after LOGIN_MAX_FAILURES wrong passwords (per email
    and per IP address), which stops password guessing.
  * Error messages never say whether an email exists ("Wrong email or password").
"""

from flask import (Blueprint, current_app, flash, g, redirect, render_template, request,
                   session, url_for)

from config import settings
from dashboard.security import (audit, clean_email, client_ip, hash_password, log_user_in,
                                login_required, password_matches, password_problem,
                                safe_next_url)
from database import db

accounts_bp = Blueprint("accounts", __name__)


def db_path():
    return current_app.config["DATABASE_PATH"]


def registration_allowed():
    # Even with sign-up closed, the very first (admin) account can be created
    return settings.REGISTRATION_OPEN or db.count_users(db_path()) == 0


@accounts_bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard.index"))
    if not registration_allowed():
        return render_template("message.html", title="Sign-up closed",
                               message="New accounts are not being accepted right now."), 403

    error = None
    email = ""
    if request.method == "POST":
        email = clean_email(request.form.get("email"))
        password = request.form.get("password", "")
        if not email:
            error = "Please enter a valid email address."
        elif password != request.form.get("password_again", ""):
            error = "The two passwords are not the same."
        elif password_problem(password):
            error = password_problem(password)
        elif not request.form.get("accept_terms"):
            error = "You must accept the terms of use."
        elif db.get_user_by_email(db_path(), email):
            error = "An account with this email already exists. Try logging in."
        else:
            first_user = db.count_users(db_path()) == 0
            user_id = db.create_user(db_path(), email, hash_password(password), is_admin=first_user)
            if first_user:
                db.claim_orphan_scans(db_path(), user_id)
            user = db.get_user(db_path(), user_id)
            log_user_in(user)
            audit("account_created", "first account (admin)" if first_user else "", user=user)
            flash("Welcome! Your account is ready.")
            return redirect(url_for("dashboard.index"))
        email = request.form.get("email", "")
    return render_template("register.html", error=error, email=email,
                           first_user=db.count_users(db_path()) == 0)


@accounts_bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard.index"))
    error = None
    email = ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password", "")
        ip = client_ip()
        failures = db.recent_login_failures(db_path(), email, ip, settings.LOGIN_LOCK_MINUTES)
        if failures >= settings.LOGIN_MAX_FAILURES:
            error = (f"Too many failed logins. Please wait {settings.LOGIN_LOCK_MINUTES} "
                     "minutes and try again.")
        else:
            user = db.get_user_by_email(db_path(), email)
            if user and password_matches(user["password_hash"], password):
                db.record_login_attempt(db_path(), email, ip, success=True)
                db.record_login(db_path(), user["id"])
                log_user_in(user)
                audit("login", user=user)
                return redirect(safe_next_url(request.args.get("next")))
            db.record_login_attempt(db_path(), email, ip, success=False)
            audit("login_failed", email, user=None)
            error = "Wrong email or password."
    return render_template("login.html", error=error, email=email,
                           can_register=registration_allowed(),
                           no_users=db.count_users(db_path()) == 0)


@accounts_bp.route("/logout", methods=["POST"])
def logout():
    if g.user:
        audit("logout")
    session.clear()
    return redirect(url_for("accounts.login"))


@accounts_bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    message = error = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "notifications":
            db.set_email_notifications(db_path(), g.user["id"], bool(request.form.get("notify")))
            message = "Notification setting saved."
        elif action == "password":
            new_password = request.form.get("new_password", "")
            if not password_matches(g.user["password_hash"], request.form.get("current_password", "")):
                error = "Your current password is wrong."
            elif password_problem(new_password):
                error = password_problem(new_password)
            else:
                db.update_password(db_path(), g.user["id"], hash_password(new_password))
                audit("password_changed")
                message = "Password changed."
        elif action == "delete_scans":
            for scan in db.list_scans(db_path(), user_id=g.user["id"]):
                if scan["status"] not in ("queued", "running"):
                    db.delete_scan(db_path(), scan["id"])
            audit("scans_deleted", "all finished scans")
            message = "All your finished scans were deleted."
        elif action == "delete_account":
            if not password_matches(g.user["password_hash"], request.form.get("confirm_password", "")):
                error = "Your password is wrong, the account was not deleted."
            else:
                audit("account_deleted", g.user["email"])
                db.delete_user(db_path(), g.user["id"])
                session.clear()
                flash("Your account and all your data were deleted.")
                return redirect(url_for("accounts.login"))
        g.user = db.get_user(db_path(), g.user["id"])

    from scanner.engine.notify import email_enabled
    return render_template("account.html", message=message, error=error,
                           email_enabled=email_enabled(),
                           retention_days=settings.RETENTION_DAYS,
                           activity=db.list_audit_log(db_path(), user_id=g.user["id"], limit=30))

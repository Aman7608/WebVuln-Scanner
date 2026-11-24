"""
Web security helpers used by every page.

  * Passwords are stored as slow, salted hashes (werkzeug's scrypt), never as text.
  * CSRF protection: every form and every JavaScript POST must send a secret
    token that only our own pages know. Another website cannot read it, so it
    cannot make your browser start scans or delete data behind your back.
  * login_required / admin_required protect pages.
  * client_ip() gives the visitor's IP address (used for logs and rate limits).
"""

import functools
import hmac
import re
import secrets

from flask import abort, current_app, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from database import db

MIN_PASSWORD_LENGTH = 10
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[a-zA-Z]{2,}$")


# ---------------------------------------------------------------- passwords
def hash_password(password):
    return generate_password_hash(password)


def password_matches(password_hash, password):
    return check_password_hash(password_hash, password)


def password_problem(password):
    """Return a message if the password is too weak, otherwise None."""
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return f"The password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if password.lower() in ("password123", "1234567890", "qwertyuiop"):
        return "That password is too common."
    return None


def clean_email(email):
    email = (email or "").strip().lower()
    return email if EMAIL_PATTERN.match(email) else None


# ---------------------------------------------------------------- CSRF
def csrf_token():
    """The secret token for this browser session (made on first use)."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def check_csrf():
    """Called before every POST request. Stops the request if the token is wrong."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    # compare_digest takes the same time for right and wrong tokens (no timing leaks)
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, "Your form expired or came from another website. Please reload the page and try again.")


# ---------------------------------------------------------------- logged-in user
def load_current_user():
    """Runs before every request: puts the logged-in user (or None) in g.user."""
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        g.user = db.get_user(current_app.config["DATABASE_PATH"], user_id)
        if g.user is None:          # account was deleted
            session.clear()


def log_user_in(user):
    session.clear()                 # new session id after login (stops session fixation)
    session["user_id"] = user["id"]
    session.permanent = True
    csrf_token()


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            if request.path.startswith("/api/"):
                abort(401)
            return redirect(url_for("accounts.login", next=request.path))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @functools.wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if not g.user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def can_see_scan(scan):
    """Users see their own scans. Admins can see every scan (for abuse reports)."""
    return g.user is not None and (scan["user_id"] == g.user["id"] or bool(g.user["is_admin"]))


def safe_next_url(target):
    """Only redirect to paths on this site after login (no open redirect!)."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("dashboard.index")


def client_ip():
    return request.remote_addr or ""


def audit(action, detail="", user=None):
    db.log_event(current_app.config["DATABASE_PATH"], action, user=user or g.get("user"),
                 detail=detail, ip_address=client_ip())

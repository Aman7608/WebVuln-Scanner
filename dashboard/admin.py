"""
Pages anyone can see (terms of use, report abuse) and the admin area.

Admin area (only for admins):
  /admin            overview: numbers for the whole service, open reports, latest activity
  /admin/users      block / unblock, make or remove admin, reset password, delete
  /admin/scans      every user's scans (filter by status)
  /admin/reports    abuse reports with the scans of the reported website
  /admin/settings   change limits and sign-up without a restart
  /admin/audit      the audit log, searchable by email

Safety rules: an admin cannot block, demote or delete their own account, and
the last admin can never be removed (otherwise nobody could manage the app).
Every admin action is written to the audit log.
"""

import secrets

from flask import (Blueprint, current_app, flash, g, redirect, render_template, request,
                   url_for)

from config import live_settings, settings
from dashboard.security import admin_required, audit, clean_email, client_ip, hash_password
from database import db
from scanner import ownership

admin_bp = Blueprint("admin", __name__)

SCAN_STATUSES = ["queued", "running", "completed", "failed", "cancelled"]


def db_path():
    return current_app.config["DATABASE_PATH"]


# ------------------------------------------------------------------ public pages
@admin_bp.route("/terms")
def terms():
    return render_template("terms.html", settings=settings,
                           live=live_settings.get_all(db_path()))


@admin_bp.route("/report-abuse", methods=["GET", "POST"])
def report_abuse():
    error = None
    if request.method == "POST":
        email = clean_email(request.form.get("email"))
        website = (request.form.get("website") or "").strip()[:300]
        message = (request.form.get("message") or "").strip()[:3000]
        if not email:
            error = "Please enter a valid email address so we can reply."
        elif not website or not message:
            error = "Please fill in the website and describe what happened."
        else:
            db.create_abuse_report(db_path(), email, website, message, client_ip())
            audit("abuse_reported", website)
            return render_template("message.html", title="Thank you",
                                   message="Your report was received. We will look into it.")
    return render_template("report_abuse.html", error=error, form=request.form)


# ------------------------------------------------------------------ admin: overview
@admin_bp.route("/admin")
@admin_required
def admin_home():
    open_reports = [r for r in db.list_abuse_reports(db_path()) if r["status"] == "open"]
    return render_template("admin/overview.html", stats=db.service_stats(db_path()),
                           open_reports=open_reports[:5],
                           events=db.list_audit_log(db_path(), limit=15))


# ------------------------------------------------------------------ admin: users
@admin_bp.route("/admin/users")
@admin_required
def users():
    return render_template("admin/users.html", users=db.list_users(db_path()))


def load_other_user(user_id):
    """Return the user, or None (with a message) if the admin may not change them."""
    user = db.get_user(db_path(), user_id)
    if user is None:
        flash("That user does not exist any more.", "error")
        return None
    if user["id"] == g.user["id"]:
        flash("You cannot do this to your own account.", "error")
        return None
    return user


@admin_bp.route("/admin/users/<int:user_id>/block", methods=["POST"])
@admin_required
def block_user(user_id):
    user = load_other_user(user_id)
    if user:
        block = not user["is_blocked"]
        if block and user["is_admin"] and db.count_admins(db_path()) <= 1:
            flash("You cannot block the last admin.", "error")
        else:
            db.set_blocked(db_path(), user_id, block)
            audit("user_blocked" if block else "user_unblocked", user["email"])
            flash(f"{user['email']} was {'blocked. Their waiting and running scans were cancelled' if block else 'unblocked'}.")
    return redirect(url_for("admin.users"))


@admin_bp.route("/admin/users/<int:user_id>/admin", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    user = load_other_user(user_id)
    if user:
        make_admin = not user["is_admin"]
        if not make_admin and db.count_admins(db_path()) <= 1:
            flash("You cannot remove the last admin.", "error")
        elif make_admin and user["is_blocked"]:
            flash("Unblock the user before making them an admin.", "error")
        else:
            db.set_admin(db_path(), user_id, make_admin)
            audit("admin_granted" if make_admin else "admin_removed", user["email"])
            flash(f"{user['email']} is {'now an admin' if make_admin else 'no longer an admin'}.")
    return redirect(url_for("admin.users"))


@admin_bp.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def reset_password(user_id):
    user = load_other_user(user_id)
    if not user:
        return redirect(url_for("admin.users"))
    temporary = secrets.token_urlsafe(12)     # random, about 16 characters
    db.set_temporary_password(db_path(), user_id, hash_password(temporary))
    audit("password_reset_by_admin", user["email"])
    # Shown once on this page only (never stored or emailed in plain text)
    return render_template("admin/password_reset.html", user=user, temporary=temporary)


@admin_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = load_other_user(user_id)
    if user:
        if user["is_admin"] and db.count_admins(db_path()) <= 1:
            flash("You cannot delete the last admin.", "error")
        else:
            db.delete_user(db_path(), user_id)
            audit("user_deleted_by_admin", user["email"])
            flash(f"Deleted {user['email']} and all their data.")
    return redirect(url_for("admin.users"))


# ------------------------------------------------------------------ admin: scans
@admin_bp.route("/admin/scans")
@admin_required
def scans():
    status = request.args.get("status")
    if status not in SCAN_STATUSES:
        status = None
    return render_template("admin/scans.html", scans=db.list_all_scans(db_path(), status=status),
                           statuses=SCAN_STATUSES, current_status=status)


# ------------------------------------------------------------------ admin: abuse reports
@admin_bp.route("/admin/reports")
@admin_required
def reports():
    report_list = []
    for report in db.list_abuse_reports(db_path()):
        try:
            host = ownership.clean_host(report["website"])
            report = dict(report, scans=db.find_scans_of_website(db_path(), host))
        except ownership.VerificationError:
            report = dict(report, scans=[])
        report_list.append(report)
    return render_template("admin/reports.html", reports=report_list)


@admin_bp.route("/admin/reports/<int:report_id>/close", methods=["POST"])
@admin_required
def close_report(report_id):
    db.close_abuse_report(db_path(), report_id)
    audit("abuse_report_closed", str(report_id))
    return redirect(url_for("admin.reports"))


# ------------------------------------------------------------------ admin: settings
@admin_bp.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def settings_page():
    error = None
    if request.method == "POST":
        try:
            changed = live_settings.save_from_form(db_path(), request.form)
        except ValueError as problem:
            error = str(problem)
        else:
            if changed:
                audit("settings_changed", ", ".join(f"{k}={v}" for k, v in changed.items()))
                flash("Settings saved.")
            else:
                flash("Nothing changed.")
            return redirect(url_for("admin.settings_page"))
    fields = [{"name": name, "kind": spec[0], "low": spec[1], "high": spec[2], "label": spec[3]}
              for name, spec in live_settings.EDITABLE.items()]
    return render_template("admin/settings.html", fields=fields, error=error,
                           values=live_settings.get_all(db_path()),
                           fixed={
                               "Mode": settings.MODE,
                               "Max pages per scan (public)": settings.PUBLIC_MAX_PAGES,
                               "Max requests per scan (public)": settings.PUBLIC_MAX_REQUESTS,
                               "Min delay between requests (public)": f"{settings.PUBLIC_MIN_DELAY} s",
                               "Login lock": f"{settings.LOGIN_MAX_FAILURES} failures -> {settings.LOGIN_LOCK_MINUTES} min",
                               "Email (SMTP)": "configured" if settings.SMTP_HOST else "not configured",
                           })


# ------------------------------------------------------------------ admin: audit log
@admin_bp.route("/admin/audit")
@admin_required
def audit_log():
    search = (request.args.get("q") or "").strip().lower()
    events = db.list_audit_log(db_path(), limit=500)
    if search:
        events = [e for e in events if search in (e["user_email"] or "").lower()
                  or search in e["action"] or search in (e["detail"] or "").lower()
                  or search in (e["ip_address"] or "")]
    return render_template("admin/audit.html", events=events[:300], search=search)

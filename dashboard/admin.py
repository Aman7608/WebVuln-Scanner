"""
Pages anyone can see (terms of use, report abuse) and the admin area.

The admin (the first account) can see all users, abuse reports with the scans
of the reported website, and the audit log. They can delete a user who
misused the service.
"""

from flask import (Blueprint, current_app, flash, g, redirect, render_template, request,
                   url_for)

from config import settings
from dashboard.security import admin_required, audit, clean_email, client_ip
from database import db
from scanner import ownership

admin_bp = Blueprint("admin", __name__)


def db_path():
    return current_app.config["DATABASE_PATH"]


@admin_bp.route("/terms")
def terms():
    return render_template("terms.html", settings=settings)


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


@admin_bp.route("/admin")
@admin_required
def admin_home():
    reports = []
    for report in db.list_abuse_reports(db_path()):
        try:
            host = ownership.clean_host(report["website"])
            report = dict(report, scans=db.find_scans_of_website(db_path(), host))
        except ownership.VerificationError:
            report = dict(report, scans=[])
        reports.append(report)
    return render_template("admin.html", users=db.list_users(db_path()), reports=reports,
                           events=db.list_audit_log(db_path(), limit=100))


@admin_bp.route("/admin/reports/<int:report_id>/close", methods=["POST"])
@admin_required
def close_report(report_id):
    db.close_abuse_report(db_path(), report_id)
    audit("abuse_report_closed", str(report_id))
    return redirect(url_for("admin.admin_home"))


@admin_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == g.user["id"]:
        flash("You cannot delete your own admin account here.", "error")
    else:
        user = db.get_user(db_path(), user_id)
        if user:
            db.delete_user(db_path(), user_id)
            audit("user_deleted_by_admin", user["email"])
            flash(f"Deleted {user['email']} and all their data.")
    return redirect(url_for("admin.admin_home"))

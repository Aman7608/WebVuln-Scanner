"""
"My websites" - add a website and prove you own it before scanning it.

See scanner/ownership.py for how the proof works (a file or a DNS record).
"""

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for

from config import settings
from dashboard.security import audit, login_required
from database import db
from scanner import ownership

domains_bp = Blueprint("domains", __name__)


def db_path():
    return current_app.config["DATABASE_PATH"]


@domains_bp.route("/websites", methods=["GET", "POST"])
@login_required
def websites():
    error = None
    if request.method == "POST":
        try:
            host = ownership.clean_host(request.form.get("host"))
            db.add_domain(db_path(), g.user["id"], host, ownership.new_token())
            audit("domain_added", host)
            return redirect(url_for("domains.websites"))
        except ownership.VerificationError as problem:
            error = str(problem)
    return render_template("websites.html", domains=db.list_domains(db_path(), g.user["id"]),
                           error=error, file_path=ownership.VERIFY_FILE_PATH,
                           dns_prefix=ownership.DNS_RECORD_PREFIX,
                           allowed_hosts=[] if settings.PUBLIC_MODE else settings.ALLOWED_HOSTS)


@domains_bp.route("/websites/<int:domain_id>/verify", methods=["POST"])
@login_required
def verify(domain_id):
    domain = db.get_domain(db_path(), g.user["id"], domain_id)
    if domain is None:
        return redirect(url_for("domains.websites"))
    try:
        method = ownership.verify(domain["host"], domain["token"])
    except ownership.VerificationError as problem:
        audit("domain_verify_failed", domain["host"])
        flash(str(problem), "error")
    else:
        db.mark_domain_verified(db_path(), domain_id, method)
        audit("domain_verified", f"{domain['host']} ({method})")
        flash(f"{domain['host']} is verified. You can scan it now.")
    return redirect(url_for("domains.websites"))


@domains_bp.route("/websites/<int:domain_id>/delete", methods=["POST"])
@login_required
def delete(domain_id):
    domain = db.get_domain(db_path(), g.user["id"], domain_id)
    if domain:
        db.delete_domain(db_path(), g.user["id"], domain_id)
        audit("domain_removed", domain["host"])
    return redirect(url_for("domains.websites"))

"""
Dashboard routes - the scan pages and the JSON API. All of them need a login.

Pages (HTML):
  /                        dashboard with totals and recent scans (your own)
  /scan                    form to start a new scan
  /scans/<id>              results of one scan (shows progress while it runs)
  /history                 list of your scans
  /scans/<id>/report.html  HTML report  (add ?download=1 to save it)
  /scans/<id>/report.pdf   PDF report, plus findings.json and findings.csv
  POST /scans/<id>/delete  delete a finished scan

API (JSON, used by static/js/scan.js):
  POST /api/scans              put a new scan in the queue
  GET  /api/scans/<id>         status and progress of a scan
  POST /api/scans/<id>/cancel  stop a scan

Users can only see their own scans (admins can see all). Someone else's scan
gives "404 not found", so nobody can even learn which scan numbers exist.
"""

import logging
from urllib.parse import urlparse

from flask import (Blueprint, Response, abort, current_app, flash, g, jsonify, redirect,
                   render_template, request, url_for)

from config import settings
from dashboard.security import audit, can_see_scan, login_required
from database import db
from reports.report_generator import (generate_csv_report, generate_html_report,
                                      generate_json_report, generate_pdf_report)
from scanner.engine.scan_engine import (DEFAULT_MODULES, QuotaError, build_config,
                                        build_secrets, cancel_scan, create_scan)
from scanner.target_manager import TargetError

logger = logging.getLogger(__name__)
dashboard_bp = Blueprint("dashboard", __name__)

MODULE_LABELS = {
    "headers": "Security headers",
    "xss": "Reflected XSS",
    "stored_xss": "Stored XSS (saves test data)",
    "sqli": "SQL injection",
    "cmdi": "Command injection",
    "redirect": "Open redirect",
    "directories": "Common files and folders",
}


def db_path():
    return current_app.config["DATABASE_PATH"]


def load_scan_or_404(scan_id):
    scan = db.get_scan(db_path(), scan_id)
    if scan is None or not can_see_scan(scan):
        abort(404)
    return scan


# ------------------------------------------------------------------ pages
@dashboard_bp.route("/")
@login_required
def index():
    return render_template("index.html",
                           stats=db.dashboard_stats(db_path(), user_id=g.user["id"]),
                           recent_scans=db.list_scans(db_path(), user_id=g.user["id"], limit=5))


@dashboard_bp.route("/scan")
@login_required
def new_scan():
    public = settings.PUBLIC_MODE
    defaults = {
        "max_depth": settings.DEFAULT_MAX_DEPTH, "max_pages": settings.DEFAULT_MAX_PAGES,
        "timeout": settings.DEFAULT_TIMEOUT, "max_requests": settings.DEFAULT_MAX_REQUESTS,
        "delay": settings.PUBLIC_MIN_DELAY if public else settings.DEFAULT_REQUEST_DELAY,
    }
    limits = {
        "max_depth": settings.LIMIT_MAX_DEPTH,
        "max_pages": settings.PUBLIC_MAX_PAGES if public else settings.LIMIT_MAX_PAGES,
        "timeout": settings.LIMIT_TIMEOUT,
        "max_requests": settings.PUBLIC_MAX_REQUESTS if public else settings.LIMIT_MAX_REQUESTS,
        "delay": settings.LIMIT_REQUEST_DELAY,
    }
    verified = [d["host"] for d in db.list_domains(db_path(), g.user["id"]) if d["verified_at"]]
    return render_template("scan.html", defaults=defaults, limits=limits,
                           modules=MODULE_LABELS, default_modules=DEFAULT_MODULES,
                           allowed_hosts=[] if public else settings.ALLOWED_HOSTS,
                           verified_hosts=verified,
                           excluded_paths=", ".join(settings.DEFAULT_EXCLUDED_PATHS))


@dashboard_bp.route("/scans/<int:scan_id>")
@login_required
def results(scan_id):
    scan = load_scan_or_404(scan_id)
    return render_template("results.html", scan=scan,
                           findings=db.get_findings(db_path(), scan_id),
                           counts=db.severity_counts(db_path(), scan_id),
                           urls=db.get_discovered_urls(db_path(), scan_id),
                           module_labels=MODULE_LABELS)


@dashboard_bp.route("/history")
@login_required
def history():
    return render_template("history.html", scans=db.list_scans(db_path(), user_id=g.user["id"]))


@dashboard_bp.route("/scans/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    scan = load_scan_or_404(scan_id)
    if scan["status"] in ("queued", "running"):
        flash("Cancel the scan before deleting it.", "error")
        return redirect(url_for("dashboard.results", scan_id=scan_id))
    db.delete_scan(db_path(), scan_id)
    audit("scan_deleted", f"#{scan_id} {scan['target_url']}")
    flash(f"Scan #{scan_id} was deleted.")
    return redirect(url_for("dashboard.history"))


# ------------------------------------------------------------------ reports
def report_data(scan_id):
    scan = load_scan_or_404(scan_id)
    if scan["status"] in ("queued", "running"):
        abort(409, "The scan is still running. Try again when it has finished.")
    return {
        "scan": scan,
        "findings": db.get_findings(db_path(), scan_id),
        "counts": db.severity_counts(db_path(), scan_id),
        "urls": db.get_discovered_urls(db_path(), scan_id),
    }


@dashboard_bp.route("/scans/<int:scan_id>/report.html")
@login_required
def html_report(scan_id):
    html = generate_html_report(**report_data(scan_id))
    response = Response(html, mimetype="text/html")
    if request.args.get("download"):
        response.headers["Content-Disposition"] = (
            f"attachment; filename=webvuln-scan-{scan_id}-report.html")
    return response


@dashboard_bp.route("/scans/<int:scan_id>/findings.json")
@login_required
def json_export(scan_id):
    return Response(generate_json_report(**report_data(scan_id)), mimetype="application/json",
                    headers={"Content-Disposition":
                             f"attachment; filename=webvuln-scan-{scan_id}-findings.json"})


@dashboard_bp.route("/scans/<int:scan_id>/findings.csv")
@login_required
def csv_export(scan_id):
    return Response(generate_csv_report(**report_data(scan_id)), mimetype="text/csv",
                    headers={"Content-Disposition":
                             f"attachment; filename=webvuln-scan-{scan_id}-findings.csv"})


@dashboard_bp.route("/scans/<int:scan_id>/report.pdf")
@login_required
def pdf_report(scan_id):
    pdf_bytes = generate_pdf_report(**report_data(scan_id))
    return Response(pdf_bytes, mimetype="application/pdf", headers={
        "Content-Disposition": f"attachment; filename=webvuln-scan-{scan_id}-report.pdf"})


# ------------------------------------------------------------------ API
def request_is_from_dashboard():
    """Extra protection on top of the CSRF token: the API only accepts JSON,
    and if the browser says which site sent the request, it must be us."""
    if not request.is_json:
        return False
    origin = request.headers.get("Origin")
    if origin and urlparse(origin).netloc != request.host:
        return False
    return True


@dashboard_bp.route("/api/scans", methods=["POST"])
@login_required
def api_start_scan():
    if not request_is_from_dashboard():
        return jsonify(error="Requests must come from the dashboard as JSON."), 403

    data = request.get_json(silent=True) or {}
    if data.get("authorized") is not True:
        return jsonify(error="Please confirm that you are authorized to scan this target."), 400

    modules = data.get("modules", DEFAULT_MODULES)
    if not isinstance(modules, list) or not modules:
        return jsonify(error="Select at least one scan module."), 400

    config = build_config({**data, "modules": modules})
    if not config["modules"]:
        return jsonify(error="Select at least one scan module."), 400

    try:
        scan_id, target_url = create_scan(db_path(), data.get("target_url"), config,
                                          user_id=g.user["id"], secrets=build_secrets(data))
    except QuotaError as error:
        return jsonify(error=str(error)), 429
    except TargetError as error:
        audit("scan_refused", f"{data.get('target_url')}: {error}")
        return jsonify(error=str(error)), 400

    audit("scan_started", f"#{scan_id} {target_url}")
    logger.info("Queued scan %s for %s", scan_id, target_url)
    return jsonify(scan_id=scan_id, target_url=target_url), 201


@dashboard_bp.route("/api/scans/<int:scan_id>/cancel", methods=["POST"])
@login_required
def api_cancel_scan(scan_id):
    if not request_is_from_dashboard():
        return jsonify(error="Requests must come from the dashboard as JSON."), 403
    scan = db.get_scan(db_path(), scan_id)
    if scan is None or not can_see_scan(scan):
        return jsonify(error="Scan not found"), 404
    if not cancel_scan(db_path(), scan_id):
        return jsonify(error="This scan is not running."), 409
    audit("scan_cancelled", f"#{scan_id}")
    return jsonify(cancelling=True)


@dashboard_bp.route("/api/scans/<int:scan_id>")
@login_required
def api_scan_status(scan_id):
    scan = db.get_scan(db_path(), scan_id)
    if scan is None or not can_see_scan(scan):
        return jsonify(error="Scan not found"), 404
    return jsonify({key: scan[key] for key in (
        "id", "status", "progress", "current_step", "pages_found", "requests_sent",
        "finding_count", "error_message", "target_url")})


# ------------------------------------------------------------------ errors
@dashboard_bp.app_errorhandler(400)
def bad_request(error):
    if request.path.startswith("/api/"):
        return jsonify(error=error.description), 400
    return render_template("error.html", code=400, message=error.description), 400


@dashboard_bp.app_errorhandler(401)
def unauthorized(error):
    return jsonify(error="Please log in again."), 401


@dashboard_bp.app_errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, message="You are not allowed to open this page."), 403


@dashboard_bp.app_errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found"), 404
    return render_template("error.html", code=404, message="Page not found."), 404


@dashboard_bp.app_errorhandler(409)
def conflict(error):
    return render_template("error.html", code=409, message=error.description), 409

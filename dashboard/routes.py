"""
Dashboard routes - every page and API address of the web interface.

Pages (HTML):
  /                      dashboard with totals and recent scans
  /scan                  form to start a new scan
  /scans/<id>            results of one scan (shows progress while running)
  /history               list of all scans
  /scans/<id>/report.html  HTML report  (add ?download=1 to save it)
  /scans/<id>/report.pdf   PDF report

API (JSON, used by static/js/scan.js):
  POST /api/scans        start a scan
  GET  /api/scans/<id>   current status and progress of a scan
"""

import logging
from urllib.parse import urlparse

from flask import (Blueprint, Response, abort, current_app, jsonify, render_template,
                   request)

from config import settings
from database import db
from reports.report_generator import (generate_csv_report, generate_html_report,
                                      generate_json_report, generate_pdf_report)
from scanner.engine.scan_engine import (DEFAULT_MODULES, build_config, build_secrets,
                                        cancel_scan, create_scan,
                                        start_scan_in_background)
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
    if scan is None:
        abort(404)
    return scan


# ------------------------------------------------------------------ pages
@dashboard_bp.route("/")
def index():
    return render_template("index.html",
                           stats=db.dashboard_stats(db_path()),
                           recent_scans=db.list_scans(db_path(), limit=5))


@dashboard_bp.route("/scan")
def new_scan():
    defaults = {
        "max_depth": settings.DEFAULT_MAX_DEPTH, "max_pages": settings.DEFAULT_MAX_PAGES,
        "timeout": settings.DEFAULT_TIMEOUT, "max_requests": settings.DEFAULT_MAX_REQUESTS,
        "delay": settings.DEFAULT_REQUEST_DELAY,
    }
    limits = {
        "max_depth": settings.LIMIT_MAX_DEPTH, "max_pages": settings.LIMIT_MAX_PAGES,
        "timeout": settings.LIMIT_TIMEOUT, "max_requests": settings.LIMIT_MAX_REQUESTS,
        "delay": settings.LIMIT_REQUEST_DELAY,
    }
    return render_template("scan.html", defaults=defaults, limits=limits,
                           modules=MODULE_LABELS, default_modules=DEFAULT_MODULES,
                           allowed_hosts=settings.ALLOWED_HOSTS,
                           excluded_paths=", ".join(settings.DEFAULT_EXCLUDED_PATHS))


@dashboard_bp.route("/scans/<int:scan_id>")
def results(scan_id):
    scan = load_scan_or_404(scan_id)
    return render_template("results.html", scan=scan,
                           findings=db.get_findings(db_path(), scan_id),
                           counts=db.severity_counts(db_path(), scan_id),
                           urls=db.get_discovered_urls(db_path(), scan_id),
                           module_labels=MODULE_LABELS)


@dashboard_bp.route("/history")
def history():
    return render_template("history.html", scans=db.list_scans(db_path()))


# ------------------------------------------------------------------ reports
def report_data(scan_id):
    scan = load_scan_or_404(scan_id)
    if scan["status"] in ("pending", "running"):
        abort(409, "The scan is still running. Try again when it has finished.")
    return {
        "scan": scan,
        "findings": db.get_findings(db_path(), scan_id),
        "counts": db.severity_counts(db_path(), scan_id),
        "urls": db.get_discovered_urls(db_path(), scan_id),
    }


@dashboard_bp.route("/scans/<int:scan_id>/report.html")
def html_report(scan_id):
    html = generate_html_report(**report_data(scan_id))
    response = Response(html, mimetype="text/html")
    if request.args.get("download"):
        response.headers["Content-Disposition"] = (
            f"attachment; filename=webvuln-scan-{scan_id}-report.html")
    return response


@dashboard_bp.route("/scans/<int:scan_id>/findings.json")
def json_export(scan_id):
    return Response(generate_json_report(**report_data(scan_id)), mimetype="application/json",
                    headers={"Content-Disposition":
                             f"attachment; filename=webvuln-scan-{scan_id}-findings.json"})


@dashboard_bp.route("/scans/<int:scan_id>/findings.csv")
def csv_export(scan_id):
    return Response(generate_csv_report(**report_data(scan_id)), mimetype="text/csv",
                    headers={"Content-Disposition":
                             f"attachment; filename=webvuln-scan-{scan_id}-findings.csv"})


@dashboard_bp.route("/scans/<int:scan_id>/report.pdf")
def pdf_report(scan_id):
    pdf_bytes = generate_pdf_report(**report_data(scan_id))
    return Response(pdf_bytes, mimetype="application/pdf", headers={
        "Content-Disposition": f"attachment; filename=webvuln-scan-{scan_id}-report.pdf"})


# ------------------------------------------------------------------ API
def request_is_from_dashboard():
    """Simple protection against other websites starting scans in your browser.

    Browsers only let a page send a JSON POST to another site after asking
    permission (CORS), which Flask does not give. We also check the Origin header.
    """
    if not request.is_json:
        return False
    origin = request.headers.get("Origin")
    if origin and urlparse(origin).netloc != request.host:
        return False
    return True


@dashboard_bp.route("/api/scans", methods=["POST"])
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
        scan_id, target_url = create_scan(db_path(), data.get("target_url"), config)
    except TargetError as error:
        return jsonify(error=str(error)), 400

    # Password and cookie go straight to the scan thread and are never saved
    start_scan_in_background(db_path(), scan_id, target_url, config, build_secrets(data))
    logger.info("Started scan %s for %s", scan_id, target_url)
    return jsonify(scan_id=scan_id, target_url=target_url), 201


@dashboard_bp.route("/api/scans/<int:scan_id>/cancel", methods=["POST"])
def api_cancel_scan(scan_id):
    if not request_is_from_dashboard():
        return jsonify(error="Requests must come from the dashboard as JSON."), 403
    if db.get_scan(db_path(), scan_id) is None:
        return jsonify(error="Scan not found"), 404
    if not cancel_scan(scan_id):
        return jsonify(error="This scan is not running."), 409
    return jsonify(cancelling=True)


@dashboard_bp.route("/api/scans/<int:scan_id>")
def api_scan_status(scan_id):
    scan = db.get_scan(db_path(), scan_id)
    if scan is None:
        return jsonify(error="Scan not found"), 404
    return jsonify({key: scan[key] for key in (
        "id", "status", "progress", "current_step", "pages_found", "requests_sent",
        "finding_count", "error_message", "target_url")})


@dashboard_bp.app_errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="Page not found."), 404


@dashboard_bp.app_errorhandler(409)
def conflict(error):
    return render_template("error.html", code=409, message=error.description), 409

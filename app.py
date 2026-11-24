"""
WebVuln Scanner - main entry point.

On your own computer (local mode):
    python app.py
Then open http://127.0.0.1:5000, create your account and start scanning.

On a server (public mode) use the production server instead:
    python serve.py      (web app)
    python worker.py     (runs the scans)
See DEPLOYMENT.md.
"""

import logging
import os
from datetime import timedelta

from flask import Flask, g, request
from werkzeug.middleware.proxy_fix import ProxyFix

from config import settings
from config.secret_key import get_secret_key
from dashboard.accounts import accounts_bp
from dashboard.admin import admin_bp
from dashboard.domains import domains_bp
from dashboard.routes import dashboard_bp
from dashboard.security import check_csrf, csrf_token, load_current_user
from database import db


def create_app(database_path=None, start_worker=None):
    """Build and return the Flask application.

    database_path lets the tests use a temporary database instead of the real one.
    start_worker: run a scan worker thread inside the app (default: local mode yes).
    """
    app = Flask(
        __name__,
        template_folder="dashboard/templates",
        static_folder="static",
    )
    app.config["DATABASE_PATH"] = database_path or settings.DATABASE_PATH
    app.config["SECRET_KEY"] = get_secret_key()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,               # JavaScript cannot read the login cookie
        SESSION_COOKIE_SAMESITE="Lax",              # other sites cannot send it in POSTs
        SESSION_COOKIE_SECURE=settings.PUBLIC_MODE,  # public mode: only over HTTPS
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
        MAX_CONTENT_LENGTH=1024 * 1024,             # refuse request bodies over 1 MB
    )
    if settings.BEHIND_PROXY:
        # Trust ONE proxy (Caddy) for the real visitor IP and https scheme
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Make sure the database file and tables exist before the first request
    db.init_db(app.config["DATABASE_PATH"])

    app.register_blueprint(accounts_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(domains_bp)
    app.register_blueprint(admin_bp)

    @app.before_request
    def before_every_request():
        load_current_user()
        check_csrf()

    @app.context_processor
    def template_helpers():
        # Available in every template: {{ csrf_token() }}, {{ current_user }}, {{ public_mode }}
        return {"csrf_token": csrf_token, "current_user": g.get("user"),
                "public_mode": settings.PUBLIC_MODE}

    @app.after_request
    def add_security_headers(response):
        # Our own dashboard should pass the same header checks it runs on others.
        # The HTML report has its CSS inside the file, so it gets its own policy.
        if request.path.endswith("/report.html"):
            policy = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
        else:
            policy = ("default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
                      "base-uri 'self'; form-action 'self'")
        response.headers.setdefault("Content-Security-Policy", policy)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if settings.PUBLIC_MODE:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    if start_worker is None:
        start_worker = settings.EMBEDDED_WORKER
    if start_worker:
        from scanner.engine.worker import start_embedded_worker
        app.config["WORKER_STOP_EVENT"] = start_embedded_worker(app.config["DATABASE_PATH"])

    return app


def setup_logging():
    """Print log messages with the time and the module name."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


if __name__ == "__main__":
    setup_logging()
    os.makedirs(settings.INSTANCE_DIR, exist_ok=True)
    if settings.PUBLIC_MODE:
        raise SystemExit("Public mode must run with the production server: python serve.py")
    flask_app = create_app()
    # debug=False on purpose: the Flask debugger must never be exposed.
    # host=127.0.0.1 means only your own computer can open the dashboard.
    flask_app.run(host=settings.DASHBOARD_HOST, port=settings.DASHBOARD_PORT, debug=False)

"""
WebVuln Scanner - main entry point.

Run this file to start the web dashboard:
    python app.py
Then open http://127.0.0.1:5000 in your browser.
"""

import logging
import os

from flask import Flask, request

from config import settings
from database import db
from dashboard.routes import dashboard_bp


def create_app(database_path=None):
    """Build and return the Flask application.

    database_path lets the tests use a temporary database instead of the real one.
    """
    app = Flask(
        __name__,
        template_folder="dashboard/templates",
        static_folder="static",
    )
    app.config["DATABASE_PATH"] = database_path or settings.DATABASE_PATH

    # Make sure the database file and tables exist before the first request
    db.init_db(app.config["DATABASE_PATH"])
    # A scan that was running when the app was closed can never finish
    db.mark_unfinished_scans_failed(app.config["DATABASE_PATH"])

    # All the pages of the dashboard live in dashboard/routes.py
    app.register_blueprint(dashboard_bp)

    @app.after_request
    def add_security_headers(response):
        # Our own dashboard should pass the same header checks it runs on others.
        # The HTML report has its CSS inside the file, so it gets its own policy.
        if request.path.endswith("/report.html"):
            policy = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
        else:
            policy = "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
        response.headers.setdefault("Content-Security-Policy", policy)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

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
    flask_app = create_app()
    # debug=False on purpose: the Flask debugger must never be exposed.
    # host=127.0.0.1 means only your own computer can open the dashboard.
    flask_app.run(host=settings.DASHBOARD_HOST, port=settings.DASHBOARD_PORT, debug=False)

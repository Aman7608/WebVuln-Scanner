"""
Run the web app with Waitress, a production-ready web server.

    python serve.py

Flask's own server (app.py) is only meant for development. Waitress handles
many visitors at once and works on both Windows and Linux. In the Docker setup
Caddy sits in front of it and adds HTTPS.

Settings come from environment variables (see .env.example).
"""

import logging

from waitress import serve

from app import create_app, setup_logging
from config import settings


def main():
    setup_logging()
    app = create_app()
    logging.info("WebVuln Scanner (%s mode) listening on %s:%s",
                 settings.MODE, settings.DASHBOARD_HOST, settings.DASHBOARD_PORT)
    serve(app, host=settings.DASHBOARD_HOST, port=settings.DASHBOARD_PORT, threads=8,
          ident="WebVuln")   # do not reveal the server software version in headers


if __name__ == "__main__":
    main()

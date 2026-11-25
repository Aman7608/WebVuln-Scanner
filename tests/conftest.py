"""
Shared test setup (pytest loads this file automatically).

The lab_url fixture starts the deliberately vulnerable test lab on a free
port on 127.0.0.1 in a background thread, so the tests can scan a real
local website without needing the internet or Docker.
"""

import os
import sys
import threading

import pytest
from werkzeug.serving import make_server

# Make "import scanner", "import config" etc. work when running pytest
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from test_lab.vulnerable_app import lab  # noqa: E402


@pytest.fixture(scope="session")
def lab_url():
    server = make_server("127.0.0.1", 0, lab)  # port 0 = pick any free port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture
def handler(lab_url):
    """A RequestHandler pointed at the lab with no delay (faster tests)."""
    from scanner.engine.request_handler import RequestHandler
    request_handler = RequestHandler(lab_url, timeout=5, max_requests=2000, delay=0)
    yield request_handler
    request_handler.close()


@pytest.fixture(autouse=True)
def fast_time_based_checks(monkeypatch):
    """Time-based checks wait 3 s in real scans. 1 s is enough in tests and much faster."""
    monkeypatch.setattr("config.settings.SQLI_TIME_DELAY", 1)


@pytest.fixture(autouse=True)
def test_settings(monkeypatch):
    """Every test starts in local mode with a fixed secret key (no file is written)."""
    monkeypatch.setattr("config.settings.SECRET_KEY", "test-secret-key-only-for-tests")
    monkeypatch.setattr("config.settings.PUBLIC_MODE", False)


@pytest.fixture
def db_path(tmp_path):
    from database import db
    path = str(tmp_path / "test.db")
    db.init_db(path)
    return path


@pytest.fixture
def app(tmp_path):
    """The web app with its own empty database and a scan worker thread."""
    from app import create_app
    flask_app = create_app(database_path=str(tmp_path / "web.db"), start_worker=True)
    flask_app.config["TESTING"] = True
    yield flask_app
    flask_app.config["WORKER_STOP_EVENT"].set()   # stop the worker thread


@pytest.fixture
def client(app):
    return app.test_client()


# ------------------------------------------------------------------ helpers for tests
def csrf_from(client):
    """Read the CSRF token from the current browser session (like a real page would)."""
    with client.session_transaction() as session:
        if "csrf_token" not in session:
            session["csrf_token"] = "test-csrf-token"
        return session["csrf_token"]


def register(client, email="alice@example.com", password="correct-horse-battery"):
    client.get("/register")
    return client.post("/register", data={
        "email": email, "password": password, "password_again": password,
        "accept_terms": "on", "csrf_token": csrf_from(client)})


def login(client, email="alice@example.com", password="correct-horse-battery"):
    return client.post("/login", data={"email": email, "password": password,
                                       "csrf_token": csrf_from(client)})


def post_json(client, url, body=None, **kwargs):
    """POST JSON to the API with the CSRF header, like static/js/common.js does."""
    return client.post(url, json=body or {}, headers={"X-CSRF-Token": csrf_from(client)}, **kwargs)


@pytest.fixture
def user_client(client):
    """A client that is logged in as a fresh user (the first user = admin)."""
    register(client)
    return client

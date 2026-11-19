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

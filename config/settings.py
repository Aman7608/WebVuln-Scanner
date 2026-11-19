"""
Settings for WebVuln Scanner.

All the numbers and lists that control how the scanner behaves live here,
so you can change them in one place. Some values can also be set with
environment variables (for example WEBVULN_ALLOWED_HOSTS).
"""

import os

# Folder that contains this project (one level up from this file)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# Authorized targets (allowlist)
# ---------------------------------------------------------------------------
# The scanner will ONLY scan hosts in this list. This stops you from scanning
# a website by accident that you do not have permission to test.
# Add more hosts with an environment variable, separated by commas:
#   set WEBVULN_ALLOWED_HOSTS=localhost,127.0.0.1,staging.mysite.test
_default_hosts = "localhost,127.0.0.1"
ALLOWED_HOSTS = [
    host.strip().lower()
    for host in os.environ.get("WEBVULN_ALLOWED_HOSTS", _default_hosts).split(",")
    if host.strip()
]

# ---------------------------------------------------------------------------
# Scan limits (default values shown on the New Scan page)
# ---------------------------------------------------------------------------
DEFAULT_MAX_DEPTH = 2        # how many links deep the crawler goes
DEFAULT_MAX_PAGES = 30       # most pages the crawler will visit
DEFAULT_TIMEOUT = 10         # seconds to wait for each request
DEFAULT_MAX_REQUESTS = 600   # most HTTP requests one scan may send
DEFAULT_REQUEST_DELAY = 0.05 # seconds to wait between requests (be polite)

# Hard upper limits, so a user cannot set something huge in the form
LIMIT_MAX_DEPTH = 5
LIMIT_MAX_PAGES = 200
LIMIT_TIMEOUT = 30
LIMIT_MAX_REQUESTS = 3000
LIMIT_REQUEST_DELAY = 5

# URLs containing any of these words are never requested. They are links
# that could log us out or change/delete data on the test site.
# You can edit this list on the New Scan page for each scan.
DEFAULT_EXCLUDED_PATHS = ["logout", "logoff", "signout", "sign-out", "log-out",
                          "delete", "remove", "reset", "setup"]

# Seconds the time-based SQL injection test asks the database to wait
SQLI_TIME_DELAY = 3

# Text sent in the User-Agent header so server owners can see who is testing
USER_AGENT = "WebVulnScanner/1.0 (authorized security testing)"

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DATABASE_PATH = os.environ.get(
    "WEBVULN_DB_PATH", os.path.join(INSTANCE_DIR, "webvuln.db")
)

# ---------------------------------------------------------------------------
# Web dashboard
# ---------------------------------------------------------------------------
DASHBOARD_HOST = "127.0.0.1"   # only reachable from this computer
DASHBOARD_PORT = int(os.environ.get("WEBVULN_PORT", "5000"))

"""
Settings for WebVuln Scanner.

All the numbers and lists that control how the scanner behaves live here,
so you can change them in one place. Some values can also be set with
environment variables (for example WEBVULN_ALLOWED_HOSTS).
"""

import os

# Folder that contains this project (one level up from this file)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def env_flag(name, default):
    """Read an on/off environment variable such as WEBVULN_REGISTRATION=0."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Mode: "local" or "public"
# ---------------------------------------------------------------------------
# local  = on your own computer. Uses the allowlist below, may scan localhost
#          (for example the test lab). Scans run inside the web app.
# public = on a server for other people. Every user must PROVE they own a
#          website before scanning it, internal/private addresses are always
#          blocked, quotas apply and scans run in a separate worker process.
MODE = os.environ.get("WEBVULN_MODE", "local").strip().lower()
if MODE not in ("local", "public"):
    raise ValueError("WEBVULN_MODE must be 'local' or 'public'")
PUBLIC_MODE = MODE == "public"

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
# Public mode limits (stop one user from overloading the service or a website)
# ---------------------------------------------------------------------------
PUBLIC_MAX_PAGES = 50
PUBLIC_MAX_REQUESTS = 1000
PUBLIC_MIN_DELAY = 0.2               # at least 0.2 s between requests
SCANS_PER_DAY = int(os.environ.get("WEBVULN_SCANS_PER_DAY", "5"))
MAX_RUNNING_SCANS_PER_USER = 1
RETENTION_DAYS = int(os.environ.get("WEBVULN_RETENTION_DAYS", "30"))  # old scans are deleted

# Login protection: after this many failed logins, wait before trying again
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_MINUTES = 15
REGISTRATION_OPEN = env_flag("WEBVULN_REGISTRATION", True)

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
# Either a SQLite file path (default) or a PostgreSQL URL such as
#   postgresql://webvuln:password@db:5432/webvuln
DATABASE_PATH = os.environ.get(
    "WEBVULN_DATABASE_URL",
    os.environ.get("WEBVULN_DB_PATH", os.path.join(INSTANCE_DIR, "webvuln.db")),
)

# Secret key: signs login cookies and encrypts scan passwords while they wait in
# the queue. In public mode it MUST come from the environment.
SECRET_KEY = os.environ.get("WEBVULN_SECRET_KEY", "")

# ---------------------------------------------------------------------------
# Scan workers
# ---------------------------------------------------------------------------
# Local mode runs one worker thread inside the web app, so "python app.py"
# is still all you need. Public mode runs "python worker.py" separately.
EMBEDDED_WORKER = env_flag("WEBVULN_EMBEDDED_WORKER", not PUBLIC_MODE)
WORKER_POLL_SECONDS = 1.0
STALE_SCAN_MINUTES = 3   # a running scan with no progress for this long is marked failed

# ---------------------------------------------------------------------------
# Email (optional): "your scan has finished" messages
# ---------------------------------------------------------------------------
SMTP_HOST = os.environ.get("WEBVULN_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("WEBVULN_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("WEBVULN_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("WEBVULN_SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("WEBVULN_SMTP_FROM", "")
PUBLIC_BASE_URL = os.environ.get("WEBVULN_PUBLIC_URL", "").rstrip("/")  # used in email links

# ---------------------------------------------------------------------------
# Web dashboard
# ---------------------------------------------------------------------------
DASHBOARD_HOST = os.environ.get("WEBVULN_HOST", "127.0.0.1")   # local: only this computer
DASHBOARD_PORT = int(os.environ.get("WEBVULN_PORT", "5000"))
# Set to 1 when running behind a reverse proxy (Caddy/Nginx) that adds X-Forwarded-* headers
BEHIND_PROXY = env_flag("WEBVULN_BEHIND_PROXY", False)

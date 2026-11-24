"""
Database tables (the "schema").

The app works with two databases:
  * SQLite     - a single file, comes with Python. Used on your own computer.
  * PostgreSQL - a database server. Used for a public deployment, because it
                 handles many users and several worker processes at once.

The schema below is written for SQLite. db.py makes the few small changes
PostgreSQL needs (for example AUTOINCREMENT -> SERIAL).

Tables:
  users            accounts that can log in
  domains          websites a user has PROVEN they own (ownership verification)
  targets          every URL that was scanned
  scans            one row per scan: owner, status, settings, progress
  discovered_urls  pages the crawler found + paths checked by directory discovery
  findings         every vulnerability found, linked to its scan
  audit_log        who did what and when (logins, scans, deletions)
  login_attempts   used to slow down password guessing
  abuse_reports    reports from people who think the scanner was misused
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    notify_by_email INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    last_login_at   TEXT
);

CREATE TABLE IF NOT EXISTS domains (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host          TEXT NOT NULL,
    token         TEXT NOT NULL,          -- random code the owner must publish
    verified_at   TEXT,                   -- empty until ownership is proven
    verify_method TEXT DEFAULT '',        -- 'file' or 'dns'
    created_at    TEXT NOT NULL,
    UNIQUE (user_id, host)
);

CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL UNIQUE,
    host        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id        INTEGER NOT NULL REFERENCES targets(id),
    user_id          INTEGER REFERENCES users(id) ON DELETE CASCADE,
    status           TEXT NOT NULL,          -- queued, running, completed, failed, cancelled
    progress         INTEGER NOT NULL DEFAULT 0,   -- 0 to 100
    current_step     TEXT DEFAULT '',
    config_json      TEXT NOT NULL,          -- the scan settings as JSON text
    pages_found      INTEGER NOT NULL DEFAULT 0,
    requests_sent    INTEGER NOT NULL DEFAULT 0,
    error_message    TEXT DEFAULT '',
    started_at       TEXT NOT NULL,          -- when the scan was requested
    finished_at      TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    heartbeat_at     TEXT,                   -- last sign of life from the worker
    secrets_enc      TEXT DEFAULT ''         -- encrypted login password/cookie, wiped when the scan starts
);

CREATE TABLE IF NOT EXISTS discovered_urls (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    status_code  INTEGER,
    depth        INTEGER,
    source       TEXT NOT NULL              -- 'crawler' or 'directory'
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    vuln_type    TEXT NOT NULL,
    url          TEXT NOT NULL,
    parameter    TEXT,
    severity     TEXT NOT NULL,
    risk_score   REAL NOT NULL,
    confidence   TEXT NOT NULL,
    description  TEXT NOT NULL,
    evidence     TEXT,
    remediation  TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,                   -- kept even if the user is deleted
    user_email  TEXT,
    action      TEXT NOT NULL,             -- e.g. login, scan_started, domain_verified
    detail      TEXT DEFAULT '',
    ip_address  TEXT DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT NOT NULL,
    ip_address   TEXT NOT NULL,
    success      INTEGER NOT NULL,
    attempted_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS abuse_reports (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_email TEXT NOT NULL,
    website        TEXT NOT NULL,
    message        TEXT NOT NULL,
    ip_address     TEXT DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'open',   -- open or closed
    created_at     TEXT NOT NULL
);
"""

# Indexes make common lookups fast. They are created after old databases
# have been upgraded (the scans.user_id column must exist first).
INDEXES = """
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_urls_scan ON discovered_urls(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_login_email ON login_attempts(email);
"""

# Columns added in version 2. Older local databases get them added automatically.
NEW_SCAN_COLUMNS = {
    "user_id": "INTEGER REFERENCES users(id) ON DELETE CASCADE",
    "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
    "heartbeat_at": "TEXT",
    "secrets_enc": "TEXT DEFAULT ''",
}

# Possible values of scans.status
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
ACTIVE_STATUSES = (STATUS_QUEUED, STATUS_RUNNING)

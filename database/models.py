"""
Database tables (the "schema").

We use SQLite, a database stored in a single file. It comes with Python, so
nothing extra needs to be installed. There are four tables:

  targets          the websites that were scanned
  scans            one row per scan: status, timestamps, settings, progress
  discovered_urls  every page the crawler found + paths checked by directory discovery
  findings         every vulnerability found, linked to its scan
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL UNIQUE,
    host        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    status          TEXT NOT NULL,          -- pending, running, completed, failed, cancelled
    progress        INTEGER NOT NULL DEFAULT 0,   -- 0 to 100
    current_step    TEXT DEFAULT '',
    config_json     TEXT NOT NULL,          -- the scan settings as JSON text
    pages_found     INTEGER NOT NULL DEFAULT 0,
    requests_sent   INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT DEFAULT '',
    started_at      TEXT NOT NULL,
    finished_at     TEXT
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

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_urls_scan ON discovered_urls(scan_id);
"""

# Possible values of scans.status
STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"

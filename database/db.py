"""
Database functions - every read and write goes through here.

Works with two databases:
  * SQLite     when settings.DATABASE_PATH is a file path (your own computer)
  * PostgreSQL when it starts with postgresql:// (a public server)

Each function opens its own short connection. That keeps things simple and
safe, because scans run in other threads or processes.

All queries use "?" placeholders (parameterized queries), so values can never
change the SQL itself - the same protection we recommend in our SQLi findings!
For PostgreSQL the "?" are turned into "%s", which is what its driver expects.
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta

from database.models import (ACTIVE_STATUSES, INDEXES, NEW_SCAN_COLUMNS, SCHEMA,
                             STATUS_CANCELLED, STATUS_COMPLETED, STATUS_FAILED,
                             STATUS_QUEUED, STATUS_RUNNING)

SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]


def now():
    """Current time as text, e.g. 2026-11-20 14:05:33 (text sorts correctly by date)."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def time_ago(minutes=0, days=0):
    return (datetime.now() - timedelta(minutes=minutes, days=days)).strftime("%Y-%m-%d %H:%M:%S")


def is_postgres(db_path):
    return str(db_path).startswith(("postgresql://", "postgres://"))


# ---------------------------------------------------------------- connections
class Connection:
    """A thin wrapper so the rest of the code does not care which database is used.

    Rows always come back as normal dictionaries: row["column_name"].
    """

    def __init__(self, raw, postgres):
        self.raw = raw
        self.postgres = postgres

    def _sql(self, sql):
        return sql.replace("?", "%s") if self.postgres else sql

    def execute(self, sql, params=()):
        cursor = self.raw.cursor()
        cursor.execute(self._sql(sql), params)
        return cursor

    def executemany(self, sql, rows):
        if rows:
            self.raw.cursor().executemany(self._sql(sql), rows)

    def insert(self, sql, params=()):
        """Run an INSERT and return the id of the new row."""
        if self.postgres:
            return self.execute(sql + " RETURNING id", params).fetchone()["id"]
        return self.execute(sql, params).lastrowid


def _dict_row(cursor, row):
    return {column[0]: row[index] for index, column in enumerate(cursor.description)}


@contextmanager
def connect(db_path):
    if is_postgres(db_path):
        import psycopg                      # only needed for PostgreSQL
        from psycopg.rows import dict_row
        raw = psycopg.connect(db_path, row_factory=dict_row)
        connection = Connection(raw, postgres=True)
    else:
        raw = sqlite3.connect(db_path, timeout=15)
        raw.row_factory = _dict_row
        raw.execute("PRAGMA foreign_keys = ON")
        connection = Connection(raw, postgres=False)
    try:
        yield connection
        raw.commit()
    except Exception:
        raw.rollback()
        raise
    finally:
        raw.close()


def _postgres_schema(sql):
    return (sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
               .replace(" REAL ", " DOUBLE PRECISION "))


def init_db(db_path):
    """Create the tables, and upgrade an older local database if needed."""
    if is_postgres(db_path):
        with connect(db_path) as conn:
            for statement in _postgres_schema(SCHEMA + INDEXES).split(";"):
                if statement.strip():
                    conn.execute(statement)
        return

    folder = os.path.dirname(db_path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with connect(db_path) as conn:
        conn.raw.executescript(SCHEMA)
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
        for column, definition in NEW_SCAN_COLUMNS.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {column} {definition}")
        # Version 1 used the status "pending"; those scans can never finish now
        conn.execute("UPDATE scans SET status = ?, error_message = ? WHERE status = 'pending'",
                     (STATUS_FAILED, "Stopped by an older version of the app."))
        conn.raw.executescript(INDEXES)


# ---------------------------------------------------------------- users
def create_user(db_path, email, password_hash, is_admin=False):
    with connect(db_path) as conn:
        return conn.insert(
            "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
            (email, password_hash, 1 if is_admin else 0, now()))


def get_user(db_path, user_id):
    with connect(db_path) as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_email(db_path, email):
    with connect(db_path) as conn:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def count_users(db_path):
    with connect(db_path) as conn:
        return conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]


def list_users(db_path):
    with connect(db_path) as conn:
        return conn.execute(
            """SELECT users.id, users.email, users.is_admin, users.created_at, users.last_login_at,
                      (SELECT COUNT(*) FROM scans WHERE scans.user_id = users.id) AS scan_count
               FROM users ORDER BY users.id""").fetchall()


def record_login(db_path, user_id):
    with connect(db_path) as conn:
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user_id))


def set_email_notifications(db_path, user_id, enabled):
    with connect(db_path) as conn:
        conn.execute("UPDATE users SET notify_by_email = ? WHERE id = ?",
                     (1 if enabled else 0, user_id))


def update_password(db_path, user_id, password_hash):
    with connect(db_path) as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))


def delete_user(db_path, user_id):
    """Delete a user and everything they own (scans, findings, domains)."""
    with connect(db_path) as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def claim_orphan_scans(db_path, user_id):
    """Scans made by version 1 (before accounts existed) go to the first account."""
    with connect(db_path) as conn:
        conn.execute("UPDATE scans SET user_id = ? WHERE user_id IS NULL", (user_id,))


# ---------------------------------------------------------------- login attempts
def record_login_attempt(db_path, email, ip_address, success):
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO login_attempts (email, ip_address, success, attempted_at) VALUES (?, ?, ?, ?)",
            (email, ip_address, 1 if success else 0, now()))


def recent_login_failures(db_path, email, ip_address, minutes):
    """Failed logins for this email OR from this IP address in the last few minutes."""
    with connect(db_path) as conn:
        return conn.execute(
            """SELECT COUNT(*) AS total FROM login_attempts
               WHERE success = 0 AND attempted_at >= ? AND (email = ? OR ip_address = ?)""",
            (time_ago(minutes=minutes), email, ip_address)).fetchone()["total"]


# ---------------------------------------------------------------- domains (ownership)
def add_domain(db_path, user_id, host, token):
    with connect(db_path) as conn:
        row = conn.execute("SELECT id FROM domains WHERE user_id = ? AND host = ?",
                           (user_id, host)).fetchone()
        if row:
            return row["id"]
        return conn.insert(
            "INSERT INTO domains (user_id, host, token, created_at) VALUES (?, ?, ?, ?)",
            (user_id, host, token, now()))


def list_domains(db_path, user_id):
    with connect(db_path) as conn:
        return conn.execute("SELECT * FROM domains WHERE user_id = ? ORDER BY host",
                            (user_id,)).fetchall()


def get_domain(db_path, user_id, domain_id):
    with connect(db_path) as conn:
        return conn.execute("SELECT * FROM domains WHERE id = ? AND user_id = ?",
                            (domain_id, user_id)).fetchone()


def mark_domain_verified(db_path, domain_id, method):
    with connect(db_path) as conn:
        conn.execute("UPDATE domains SET verified_at = ?, verify_method = ? WHERE id = ?",
                     (now(), method, domain_id))


def delete_domain(db_path, user_id, domain_id):
    with connect(db_path) as conn:
        conn.execute("DELETE FROM domains WHERE id = ? AND user_id = ?", (domain_id, user_id))


def is_domain_verified(db_path, user_id, host):
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT id FROM domains WHERE user_id = ? AND host = ? AND verified_at IS NOT NULL",
            (user_id, host)).fetchone()
    return row is not None


# ---------------------------------------------------------------- scans (writing)
def get_or_create_target(db_path, url, host):
    with connect(db_path) as conn:
        row = conn.execute("SELECT id FROM targets WHERE url = ?", (url,)).fetchone()
        if row:
            return row["id"]
        return conn.insert("INSERT INTO targets (url, host, created_at) VALUES (?, ?, ?)",
                           (url, host, now()))


def create_scan(db_path, target_id, config, user_id=None, secrets_enc=""):
    """Add a scan to the queue. A worker picks it up and runs it."""
    with connect(db_path) as conn:
        return conn.insert(
            """INSERT INTO scans (target_id, user_id, status, config_json, started_at, secrets_enc,
                                  current_step)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (target_id, user_id, STATUS_QUEUED, json.dumps(config), now(), secrets_enc,
             "Waiting for a free worker"))


def claim_next_scan(db_path):
    """Give the oldest queued scan to the calling worker. Returns its id or None.

    One UPDATE statement does the "find and take" in a single step, so two
    workers can never take the same scan.
    """
    lock = " FOR UPDATE SKIP LOCKED" if is_postgres(db_path) else ""
    with connect(db_path) as conn:
        row = conn.execute(
            f"""UPDATE scans SET status = ?, heartbeat_at = ?, current_step = 'Starting'
                WHERE id = (SELECT id FROM scans WHERE status = ? ORDER BY id LIMIT 1{lock})
                  AND status = ?
                RETURNING id""",
            (STATUS_RUNNING, now(), STATUS_QUEUED, STATUS_QUEUED)).fetchone()
    return row["id"] if row else None


def take_scan_secrets(db_path, scan_id):
    """Read the encrypted login secrets once and wipe them from the database."""
    with connect(db_path) as conn:
        row = conn.execute("SELECT secrets_enc FROM scans WHERE id = ?", (scan_id,)).fetchone()
        conn.execute("UPDATE scans SET secrets_enc = '' WHERE id = ?", (scan_id,))
    return (row or {}).get("secrets_enc") or ""


def update_progress(db_path, scan_id, progress, step, requests_sent=0):
    with connect(db_path) as conn:
        conn.execute(
            """UPDATE scans SET progress = ?, current_step = ?, requests_sent = ?, heartbeat_at = ?
               WHERE id = ?""",
            (int(progress), step, requests_sent, now(), scan_id))


def finish_scan(db_path, scan_id, pages_found, requests_sent, error_message="", note="Finished",
                cancelled=False):
    status = STATUS_FAILED if error_message else STATUS_COMPLETED
    if cancelled:
        status = STATUS_CANCELLED
    with connect(db_path) as conn:
        conn.execute(
            """UPDATE scans SET status = ?, progress = 100, current_step = ?, pages_found = ?,
               requests_sent = ?, error_message = ?, finished_at = ?, secrets_enc = ''
               WHERE id = ?""",
            (status, note if not error_message else "Failed", pages_found,
             requests_sent, error_message, now(), scan_id))


def request_cancel(db_path, scan_id):
    """Ask a scan to stop. A queued scan is cancelled at once; a running one stops soon."""
    with connect(db_path) as conn:
        row = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None or row["status"] not in ACTIVE_STATUSES:
            return False
        if row["status"] == STATUS_QUEUED:
            conn.execute(
                """UPDATE scans SET status = ?, current_step = 'Cancelled by the user',
                   finished_at = ?, secrets_enc = '' WHERE id = ?""",
                (STATUS_CANCELLED, now(), scan_id))
        else:
            conn.execute("UPDATE scans SET cancel_requested = 1 WHERE id = ?", (scan_id,))
    return True


def is_cancel_requested(db_path, scan_id):
    with connect(db_path) as conn:
        row = conn.execute("SELECT cancel_requested FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return bool(row and row["cancel_requested"])


def save_discovered_urls(db_path, scan_id, urls, source):
    """urls is a list of dicts with url, status_code and (optional) depth."""
    with connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO discovered_urls (scan_id, url, status_code, depth, source) VALUES (?, ?, ?, ?, ?)",
            [(scan_id, u["url"], u.get("status_code"), u.get("depth"), source) for u in urls])


def save_findings(db_path, scan_id, findings):
    with connect(db_path) as conn:
        conn.executemany(
            """INSERT INTO findings (scan_id, name, vuln_type, url, parameter, severity, risk_score,
               confidence, description, evidence, remediation, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(scan_id, f.name, f.vuln_type, f.url, f.parameter, f.severity, f.risk_score,
              f.confidence, f.description, f.evidence, f.remediation, now()) for f in findings])


def fail_stale_scans(db_path, minutes):
    """A running scan with no progress for a while belongs to a worker that died."""
    with connect(db_path) as conn:
        cursor = conn.execute(
            """UPDATE scans SET status = ?, error_message = ?, finished_at = ?, secrets_enc = ''
               WHERE status = ? AND (heartbeat_at IS NULL OR heartbeat_at <= ?)""",
            (STATUS_FAILED, "The scan worker stopped before the scan finished.", now(),
             STATUS_RUNNING, time_ago(minutes=minutes)))
        return cursor.rowcount


def delete_scan(db_path, scan_id):
    with connect(db_path) as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


def delete_old_scans(db_path, days):
    """Data retention: remove finished scans older than the given number of days."""
    with connect(db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM scans WHERE status NOT IN (?, ?) AND started_at < ?",
            (STATUS_QUEUED, STATUS_RUNNING, time_ago(days=days)))
        return cursor.rowcount


# ---------------------------------------------------------------- scans (reading)
SCAN_COLUMNS = """
    scans.*, targets.url AS target_url, targets.host AS target_host,
    (SELECT COUNT(*) FROM findings WHERE findings.scan_id = scans.id) AS finding_count
"""


def _scan_from_row(row):
    scan = dict(row)
    scan["config"] = json.loads(scan.pop("config_json"))
    scan.pop("secrets_enc", None)   # never hand secrets to pages or reports
    return scan


def get_scan(db_path, scan_id):
    with connect(db_path) as conn:
        row = conn.execute(
            f"SELECT {SCAN_COLUMNS} FROM scans JOIN targets ON targets.id = scans.target_id "
            "WHERE scans.id = ?", (scan_id,)).fetchone()
    return _scan_from_row(row) if row else None


def list_scans(db_path, user_id=None, limit=None):
    """Scans of one user (newest first). user_id=None lists every scan (admin)."""
    sql = f"SELECT {SCAN_COLUMNS} FROM scans JOIN targets ON targets.id = scans.target_id"
    params = []
    if user_id is not None:
        sql += " WHERE scans.user_id = ?"
        params.append(user_id)
    sql += " ORDER BY scans.id DESC"
    if limit:
        sql += " LIMIT ?"
        params.append(limit)
    with connect(db_path) as conn:
        return [_scan_from_row(row) for row in conn.execute(sql, params).fetchall()]


def count_scans_since(db_path, user_id, since):
    with connect(db_path) as conn:
        return conn.execute("SELECT COUNT(*) AS total FROM scans WHERE user_id = ? AND started_at >= ?",
                            (user_id, since)).fetchone()["total"]


def count_active_scans(db_path, user_id):
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT COUNT(*) AS total FROM scans WHERE user_id = ? AND status IN (?, ?)",
            (user_id, STATUS_QUEUED, STATUS_RUNNING)).fetchone()["total"]


SEVERITY_ORDER_SQL = """CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
    WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END"""


def get_findings(db_path, scan_id):
    with connect(db_path) as conn:
        return conn.execute(
            f"SELECT * FROM findings WHERE scan_id = ? ORDER BY {SEVERITY_ORDER_SQL}, risk_score DESC, id",
            (scan_id,)).fetchall()


def get_discovered_urls(db_path, scan_id):
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT * FROM discovered_urls WHERE scan_id = ? ORDER BY source, id", (scan_id,)).fetchall()


def severity_counts(db_path, scan_id=None, user_id=None):
    """Count findings per severity, for one scan, one user, or everything."""
    counts = {level: 0 for level in SEVERITIES}
    sql = "SELECT findings.severity, COUNT(*) AS total FROM findings"
    params = []
    if scan_id is not None:
        sql += " WHERE findings.scan_id = ?"
        params.append(scan_id)
    elif user_id is not None:
        sql += " JOIN scans ON scans.id = findings.scan_id WHERE scans.user_id = ?"
        params.append(user_id)
    sql += " GROUP BY findings.severity"
    with connect(db_path) as conn:
        for row in conn.execute(sql, params).fetchall():
            counts[row["severity"]] = row["total"]
    return counts


def dashboard_stats(db_path, user_id=None):
    where, params = ("WHERE user_id = ?", (user_id,)) if user_id is not None else ("", ())
    with connect(db_path) as conn:
        total_scans = conn.execute(f"SELECT COUNT(*) AS total FROM scans {where}",
                                   params).fetchone()["total"]
        total_findings = conn.execute(
            f"SELECT COUNT(*) AS total FROM findings WHERE scan_id IN (SELECT id FROM scans {where})",
            params).fetchone()["total"]
    stats = {"total_scans": total_scans, "total_findings": total_findings}
    stats.update({f"count_{k.lower()}": v for k, v in severity_counts(db_path, user_id=user_id).items()})
    return stats


# ---------------------------------------------------------------- audit log
def log_event(db_path, action, user=None, detail="", ip_address=""):
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO audit_log (user_id, user_email, action, detail, ip_address, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user["id"] if user else None, user["email"] if user else None, action,
             str(detail)[:500], ip_address or "", now()))


def list_audit_log(db_path, user_id=None, limit=200):
    sql = "SELECT * FROM audit_log"
    params = []
    if user_id is not None:
        sql += " WHERE user_id = ?"
        params.append(user_id)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with connect(db_path) as conn:
        return conn.execute(sql, params).fetchall()


# ---------------------------------------------------------------- abuse reports
def create_abuse_report(db_path, reporter_email, website, message, ip_address):
    with connect(db_path) as conn:
        return conn.insert(
            """INSERT INTO abuse_reports (reporter_email, website, message, ip_address, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (reporter_email, website, message, ip_address, now()))


def list_abuse_reports(db_path):
    with connect(db_path) as conn:
        return conn.execute("SELECT * FROM abuse_reports ORDER BY status DESC, id DESC").fetchall()


def close_abuse_report(db_path, report_id):
    with connect(db_path) as conn:
        conn.execute("UPDATE abuse_reports SET status = 'closed' WHERE id = ?", (report_id,))


def find_scans_of_website(db_path, host):
    """Admin helper for abuse reports: which users scanned this host?"""
    with connect(db_path) as conn:
        return conn.execute(
            """SELECT scans.id, scans.started_at, users.email, targets.url
               FROM scans JOIN targets ON targets.id = scans.target_id
               LEFT JOIN users ON users.id = scans.user_id
               WHERE targets.host = ? ORDER BY scans.id DESC LIMIT 50""", (host,)).fetchall()

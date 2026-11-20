"""
Database functions - every read and write to SQLite goes through here.

Each function opens its own short connection. That keeps things simple and
safe, because the scan runs in a background thread and SQLite connections
should not be shared between threads.

All queries use "?" placeholders (parameterized queries), so values can never
change the SQL itself - the same protection we recommend in our SQLi findings!
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime

from database.models import (SCHEMA, STATUS_CANCELLED, STATUS_COMPLETED, STATUS_FAILED,
                             STATUS_RUNNING)


def now():
    """Current local time as text, e.g. 2026-11-20 14:05:33"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@contextmanager
def connect(db_path):
    connection = sqlite3.connect(db_path, timeout=10)
    connection.row_factory = sqlite3.Row      # lets us use row["column_name"]
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db(db_path):
    folder = os.path.dirname(db_path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


# ---------------------------------------------------------------- writing
def get_or_create_target(db_path, url, host):
    with connect(db_path) as conn:
        row = conn.execute("SELECT id FROM targets WHERE url = ?", (url,)).fetchone()
        if row:
            return row["id"]
        cursor = conn.execute(
            "INSERT INTO targets (url, host, created_at) VALUES (?, ?, ?)", (url, host, now()))
        return cursor.lastrowid


def create_scan(db_path, target_id, config):
    with connect(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO scans (target_id, status, config_json, started_at) VALUES (?, 'pending', ?, ?)",
            (target_id, json.dumps(config), now()))
        return cursor.lastrowid


def update_progress(db_path, scan_id, progress, step, requests_sent=0):
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE scans SET status = ?, progress = ?, current_step = ?, requests_sent = ? WHERE id = ?",
            (STATUS_RUNNING, int(progress), step, requests_sent, scan_id))


def finish_scan(db_path, scan_id, pages_found, requests_sent, error_message="", note="Finished",
                cancelled=False):
    status = STATUS_FAILED if error_message else STATUS_COMPLETED
    if cancelled:
        status = STATUS_CANCELLED
    with connect(db_path) as conn:
        conn.execute(
            """UPDATE scans SET status = ?, progress = 100, current_step = ?, pages_found = ?,
               requests_sent = ?, error_message = ?, finished_at = ? WHERE id = ?""",
            (status, note if not error_message else "Failed", pages_found,
             requests_sent, error_message, now(), scan_id))


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


def mark_unfinished_scans_failed(db_path):
    """If the app was closed during a scan, that scan can never finish. Mark it failed."""
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE scans SET status = ?, error_message = ?, finished_at = ? "
            "WHERE status IN ('pending', 'running')",
            (STATUS_FAILED, "The application was stopped before the scan finished.", now()))


# ---------------------------------------------------------------- reading
SCAN_COLUMNS = """
    scans.*, targets.url AS target_url, targets.host AS target_host,
    (SELECT COUNT(*) FROM findings WHERE findings.scan_id = scans.id) AS finding_count
"""


def get_scan(db_path, scan_id):
    with connect(db_path) as conn:
        row = conn.execute(
            f"SELECT {SCAN_COLUMNS} FROM scans JOIN targets ON targets.id = scans.target_id "
            "WHERE scans.id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    scan = dict(row)
    scan["config"] = json.loads(scan.pop("config_json"))
    return scan


def list_scans(db_path, limit=None):
    sql = (f"SELECT {SCAN_COLUMNS} FROM scans JOIN targets ON targets.id = scans.target_id "
           "ORDER BY scans.id DESC")
    params = ()
    if limit:
        sql += " LIMIT ?"
        params = (limit,)
    with connect(db_path) as conn:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]


SEVERITY_ORDER_SQL = """CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
    WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END"""


def get_findings(db_path, scan_id):
    with connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM findings WHERE scan_id = ? ORDER BY {SEVERITY_ORDER_SQL}, risk_score DESC, id",
            (scan_id,)).fetchall()
    return [dict(row) for row in rows]


def get_discovered_urls(db_path, scan_id):
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM discovered_urls WHERE scan_id = ? ORDER BY source, id", (scan_id,)).fetchall()
    return [dict(row) for row in rows]


def severity_counts(db_path, scan_id=None):
    """Count findings per severity, for one scan or for all scans."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    sql = "SELECT severity, COUNT(*) AS total FROM findings"
    params = ()
    if scan_id is not None:
        sql += " WHERE scan_id = ?"
        params = (scan_id,)
    sql += " GROUP BY severity"
    with connect(db_path) as conn:
        for row in conn.execute(sql, params).fetchall():
            counts[row["severity"]] = row["total"]
    return counts


def dashboard_stats(db_path):
    with connect(db_path) as conn:
        total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    stats = {"total_scans": total_scans, "total_findings": total_findings}
    stats.update({f"count_{k.lower()}": v for k, v in severity_counts(db_path).items()})
    return stats

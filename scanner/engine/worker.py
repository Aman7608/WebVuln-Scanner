"""
Scan worker - takes scans from the queue and runs them.

The web app never scans by itself. When you press "Start scan", the scan is
saved in the database with the status "queued". A worker:
  1. claims the oldest queued scan (only one worker can get it),
  2. decrypts the login secrets (and the database copy is wiped),
  3. runs the scan, writing progress as it goes,
  4. optionally emails the owner when it is done.

Why a queue instead of starting a thread in the web app?
  * scans keep waiting safely if the web app restarts,
  * you can run several workers (even on other machines) for more scans at once,
  * the web app stays fast because it only reads and writes the database.

Local mode starts one worker thread inside the web app (start_embedded_worker),
so "python app.py" is still enough. Public mode runs "python worker.py".

The worker also does housekeeping every few minutes:
  * marks scans whose worker died as failed,
  * deletes scans older than RETENTION_DAYS (public mode).
"""

import logging
import socket
import threading
import time

from config import settings
from database import db
from scanner.engine import notify
from scanner.engine.scan_engine import run_scan
from scanner.engine.secret_box import decrypt_secrets

logger = logging.getLogger(__name__)

HOUSEKEEPING_EVERY_SECONDS = 300


def run_one(db_path):
    """Run the next queued scan. Returns its id, or None when the queue is empty."""
    scan_id = db.claim_next_scan(db_path)
    if scan_id is None:
        return None
    scan = db.get_scan(db_path, scan_id)
    secrets = decrypt_secrets(db.take_scan_secrets(db_path, scan_id))
    logger.info("Worker %s started scan %s (%s)", socket.gethostname(), scan_id, scan["target_url"])

    run_scan(db_path, scan_id, scan["target_url"], scan["config"], secrets,
             user_id=scan["user_id"])

    finished = db.get_scan(db_path, scan_id)
    if finished["user_id"] is not None:
        user = db.get_user(db_path, finished["user_id"])
        if user and user["notify_by_email"]:
            notify.send_scan_finished(user["email"], finished)
    return scan_id


def housekeeping(db_path, stale_minutes=settings.STALE_SCAN_MINUTES):
    failed = db.fail_stale_scans(db_path, stale_minutes)
    deleted = db.delete_old_scans(db_path, settings.RETENTION_DAYS) if settings.PUBLIC_MODE else 0
    if failed or deleted:
        logger.info("Housekeeping: %d stale scans failed, %d old scans deleted", failed, deleted)


def run_forever(db_path, stop_event=None):
    """Keep taking scans until stop_event is set (or forever)."""
    stop_event = stop_event or threading.Event()
    last_housekeeping = 0.0
    while not stop_event.is_set():
        try:
            if time.monotonic() - last_housekeeping > HOUSEKEEPING_EVERY_SECONDS:
                housekeeping(db_path)
                last_housekeeping = time.monotonic()
            if run_one(db_path) is None:
                stop_event.wait(settings.WORKER_POLL_SECONDS)
        except Exception:  # a broken scan must never kill the worker
            logger.exception("Worker error")
            stop_event.wait(5)


def start_embedded_worker(db_path):
    """Local mode: run the worker in a background thread of the web app.

    Any scan still marked "running" belonged to the previous run of the app,
    which has stopped, so it is marked failed first.
    """
    db.fail_stale_scans(db_path, minutes=0)
    stop_event = threading.Event()
    thread = threading.Thread(target=run_forever, args=(db_path, stop_event),
                              daemon=True, name="scan-worker")
    thread.start()
    return stop_event

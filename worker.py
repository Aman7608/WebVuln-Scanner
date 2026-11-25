"""
Start a scan worker (public mode).

    python worker.py

It keeps taking queued scans from the database and runs them. Run more than
one for more scans at the same time. In local mode you do not need this:
app.py already starts a worker inside the web app.
"""

import logging
import signal
import threading

from config import settings
from config.secret_key import get_secret_key
from database import db
from scanner.engine.worker import run_forever


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    get_secret_key()                     # stop early if the key is missing
    db.init_db(settings.DATABASE_PATH)

    stop_event = threading.Event()
    # Ctrl+C or "docker stop" ends the worker after the current scan step
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    logging.info("Worker started (mode: %s). Waiting for scans...", settings.MODE)
    run_forever(settings.DATABASE_PATH, stop_event)
    logging.info("Worker stopped.")


if __name__ == "__main__":
    main()

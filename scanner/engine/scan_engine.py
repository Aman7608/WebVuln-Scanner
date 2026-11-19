"""
Scan Engine - runs a complete scan from start to finish.

This is the "manager" that calls all the other modules in order:

  1. Target Manager   -> check the URL is valid and allowed
  2. Crawler          -> find pages, forms and parameters
  3. Header Analyzer  -> check security headers of the start page
  4. XSS Scanner      -> test parameters for reflected XSS
  5. SQLi Scanner     -> test parameters for SQL injection
  6. Redirect Scanner -> test redirect-like parameters
  7. Directory Scan   -> check a short list of common paths
  8. Save everything to the database

Progress is written to the database after each step, so the dashboard can
show a progress bar while the scan runs in a background thread.
"""

import logging
import threading

from config import settings
from database import db
from scanner.analysis.findings_collector import FindingsCollector
from scanner.crawler.crawler import Crawler
from scanner.engine.request_handler import RequestHandler, RequestLimitReached
from scanner.target_manager import TargetError, check_target
from scanner.vulnerabilities.directory_scanner import scan_directories
from scanner.vulnerabilities.header_analyzer import scan_headers
from scanner.vulnerabilities.redirect_scanner import scan_redirects
from scanner.vulnerabilities.sqli_scanner import scan_sqli
from scanner.vulnerabilities.xss_scanner import scan_xss

logger = logging.getLogger(__name__)

ALL_MODULES = ["headers", "xss", "sqli", "redirect", "directories"]


def clamp(value, low, high):
    return max(low, min(high, value))


def build_config(form):
    """Turn the values from the New Scan form into a safe config dictionary.

    Every number is limited to the ranges in config/settings.py.
    """
    def number(name, default, low, high, cast=int):
        try:
            return clamp(cast(form.get(name, default)), low, high)
        except (TypeError, ValueError):
            return default

    modules = [m for m in form.get("modules", ALL_MODULES) if m in ALL_MODULES]
    return {
        "max_depth": number("max_depth", settings.DEFAULT_MAX_DEPTH, 0, settings.LIMIT_MAX_DEPTH),
        "max_pages": number("max_pages", settings.DEFAULT_MAX_PAGES, 1, settings.LIMIT_MAX_PAGES),
        "timeout": number("timeout", settings.DEFAULT_TIMEOUT, 1, settings.LIMIT_TIMEOUT),
        "max_requests": number("max_requests", settings.DEFAULT_MAX_REQUESTS, 10,
                               settings.LIMIT_MAX_REQUESTS),
        "delay": number("delay", settings.DEFAULT_REQUEST_DELAY, 0,
                        settings.LIMIT_REQUEST_DELAY, cast=float),
        "modules": modules,
    }


def create_scan(db_path, target_url, config):
    """Check the target and create the scan row. Raises TargetError if not allowed."""
    target = check_target(target_url)
    target_id = db.get_or_create_target(db_path, target["url"], target["host"])
    scan_id = db.create_scan(db_path, target_id, config)
    return scan_id, target["url"]


def run_scan(db_path, scan_id, target_url, config):
    """Run all scan steps. Always ends with the scan marked completed or failed."""
    collector = FindingsCollector()
    handler = RequestHandler(target_url, timeout=config["timeout"],
                             max_requests=config["max_requests"], delay=config["delay"])
    modules = config["modules"]
    pages = []
    note = "Finished"

    def progress(percent, step):
        db.update_progress(db_path, scan_id, percent, step, handler.request_count)

    try:
        # Check the target again right before scanning (DNS could have changed)
        check_target(target_url)

        # ---- Step 1: crawl (0% - 40%)
        progress(2, "Crawling the website")
        crawler = Crawler(
            handler, target_url, max_depth=config["max_depth"], max_pages=config["max_pages"],
            progress_callback=lambda done, total: progress(
                2 + 38 * done / total, f"Crawling: {done} pages found"),
        )
        crawl = crawler.crawl()
        pages = crawl.pages
        db.save_discovered_urls(db_path, scan_id, pages, "crawler")
        points = crawl.injection_points

        # ---- Steps 2-6: each module that the user selected
        steps = [
            ("headers", 45, "Checking security headers",
             lambda: scan_headers(handler, target_url, collector)),
            ("xss", 60, f"Testing {len(points)} input points for XSS",
             lambda: scan_xss(handler, points, collector)),
            ("sqli", 80, "Testing for SQL injection",
             lambda: scan_sqli(handler, points, collector)),
            ("redirect", 85, "Testing for open redirects",
             lambda: scan_redirects(handler, points, collector)),
            ("directories", 98, "Checking common paths",
             lambda: db.save_discovered_urls(
                 db_path, scan_id, scan_directories(handler, target_url, collector), "directory")),
        ]
        start_percent = 40
        for name, end_percent, label, action in steps:
            if name not in modules:
                continue
            progress(start_percent, label)
            try:
                action()
            except RequestLimitReached:
                note = f"Stopped early: request limit ({config['max_requests']}) reached"
                logger.warning(note)
                break
            start_percent = end_percent

        db.save_findings(db_path, scan_id, collector.sorted_findings())
        db.finish_scan(db_path, scan_id, len(pages), handler.request_count, note=note)
        logger.info("Scan %s finished with %d findings", scan_id, len(collector.findings))

    except TargetError as error:
        db.finish_scan(db_path, scan_id, len(pages), handler.request_count, str(error))
    except Exception as error:  # never leave a scan stuck at "running"
        logger.exception("Scan %s crashed", scan_id)
        db.save_findings(db_path, scan_id, collector.sorted_findings())
        db.finish_scan(db_path, scan_id, len(pages), handler.request_count,
                       f"Unexpected error: {error}")
    finally:
        handler.close()


def start_scan_in_background(db_path, scan_id, target_url, config):
    """Run the scan in a separate thread so the web page does not freeze."""
    thread = threading.Thread(target=run_scan, args=(db_path, scan_id, target_url, config),
                              daemon=True, name=f"scan-{scan_id}")
    thread.start()
    return thread

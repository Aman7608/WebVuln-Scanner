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
show a progress bar while a worker (see worker.py) runs the scan.

Starting a scan is split in two:
  * create_scan() - runs in the web app: checks the target, the user's quota
                    and the settings, then puts the scan in the queue.
  * run_scan()    - runs in a worker: does the actual scanning.
"""

import logging

from config import settings
from database import db
from scanner.analysis.findings_collector import FindingsCollector
from scanner.crawler.crawler import Crawler
from scanner.engine.auth import LoginError, apply_cookie_string, login_with_form
from scanner.engine.request_handler import RequestHandler, RequestLimitReached, ScanCancelled
from scanner.engine.secret_box import encrypt_secrets
from scanner.target_manager import TargetError, check_target, is_in_scope, validate_url
from scanner.vulnerabilities.command_injection_scanner import scan_command_injection
from scanner.vulnerabilities.directory_scanner import scan_directories
from scanner.vulnerabilities.header_analyzer import scan_headers
from scanner.vulnerabilities.redirect_scanner import scan_redirects
from scanner.vulnerabilities.sqli_scanner import scan_sqli
from scanner.vulnerabilities.stored_xss_scanner import scan_stored_xss
from scanner.vulnerabilities.xss_scanner import scan_xss

logger = logging.getLogger(__name__)

ALL_MODULES = ["headers", "xss", "stored_xss", "sqli", "cmdi", "redirect", "directories"]
# Stored XSS saves test data on the site, so it is only run when the user ticks it
DEFAULT_MODULES = ["headers", "xss", "sqli", "cmdi", "redirect", "directories"]



class QuotaError(Exception):
    """Raised when a user has used up their scans for now (public mode)."""


def cancel_scan(db_path, scan_id):
    """Ask a scan to stop. Works from any process: the worker sees the flag in the database."""
    return db.request_cancel(db_path, scan_id)


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

    modules = [m for m in form.get("modules", DEFAULT_MODULES) if m in ALL_MODULES]

    # Excluded paths can come as a list or as text separated by commas
    excluded = form.get("exclude_paths", settings.DEFAULT_EXCLUDED_PATHS)
    if isinstance(excluded, str):
        excluded = excluded.split(",")
    excluded = [str(p).strip().lower()[:100] for p in excluded if str(p).strip()][:30]

    return {
        "max_depth": number("max_depth", settings.DEFAULT_MAX_DEPTH, 0, settings.LIMIT_MAX_DEPTH),
        "max_pages": number("max_pages", settings.DEFAULT_MAX_PAGES, 1, settings.LIMIT_MAX_PAGES),
        "timeout": number("timeout", settings.DEFAULT_TIMEOUT, 1, settings.LIMIT_TIMEOUT),
        "max_requests": number("max_requests", settings.DEFAULT_MAX_REQUESTS, 10,
                               settings.LIMIT_MAX_REQUESTS),
        "delay": number("delay", settings.DEFAULT_REQUEST_DELAY, 0,
                        settings.LIMIT_REQUEST_DELAY, cast=float),
        "modules": modules,
        "exclude_paths": excluded,
        # Only the login page and username are saved. Passwords/cookies never are.
        "login_url": (form.get("login_url") or "").strip(),
        "login_username": (form.get("login_username") or "").strip()[:100],
        "uses_cookie": bool((form.get("cookies") or "").strip()),
    }


def apply_public_limits(config):
    """Public mode: stricter limits so one user cannot hammer a website."""
    if settings.PUBLIC_MODE:
        config["max_pages"] = min(config["max_pages"], settings.PUBLIC_MAX_PAGES)
        config["max_requests"] = min(config["max_requests"], settings.PUBLIC_MAX_REQUESTS)
        config["delay"] = max(config["delay"], settings.PUBLIC_MIN_DELAY)
    return config


def check_quota(db_path, user_id):
    """Public mode: a daily scan limit and only one scan at a time per user."""
    if not settings.PUBLIC_MODE or user_id is None:
        return
    if db.count_active_scans(db_path, user_id) >= settings.MAX_RUNNING_SCANS_PER_USER:
        raise QuotaError("You already have a scan waiting or running. Wait for it to finish.")
    if db.count_scans_since(db_path, user_id, db.time_ago(days=1)) >= settings.SCANS_PER_DAY:
        raise QuotaError(f"You have reached the limit of {settings.SCANS_PER_DAY} scans per "
                         "24 hours. Please try again later.")


def build_secrets(form):
    """The sensitive login values. Kept in memory only, never in the database."""
    return {
        "password": form.get("login_password") or "",
        "cookies": (form.get("cookies") or "").strip(),
    }


def create_scan(db_path, target_url, config, user_id=None, secrets=None):
    """Check everything and put the scan in the queue.

    Raises TargetError (target not allowed) or QuotaError (too many scans).
    The login password/cookie (secrets) is stored encrypted until a worker
    starts the scan, then it is wiped.
    """
    check_quota(db_path, user_id)
    target = check_target(target_url, user_id=user_id, db_path=db_path)
    apply_public_limits(config)
    if config.get("login_url"):
        login_url = validate_url(config["login_url"])
        if not is_in_scope(login_url, target["url"]):
            raise TargetError("The login page must be on the same website as the target.")
        if not config.get("login_username"):
            raise TargetError("Please enter the username for the login page.")
        config["login_url"] = login_url
    target_id = db.get_or_create_target(db_path, target["url"], target["host"])
    scan_id = db.create_scan(db_path, target_id, config, user_id=user_id,
                             secrets_enc=encrypt_secrets(secrets or {}))
    return scan_id, target["url"]


def log_in(handler, config, secrets):
    """Apply the cookie and/or log in with the form.

    Returns (status text, URL of the page we landed on after logging in or None).
    """
    status = []
    landing_url = None
    if secrets.get("cookies"):
        count = apply_cookie_string(handler, secrets["cookies"])
        status.append(f"{count} session cookie(s) added")
    if config.get("login_url"):
        landing_page = login_with_form(handler, config["login_url"], config["login_username"],
                                       secrets.get("password", ""))
        status.append(f"logged in as {config['login_username']}")
        landing_url = landing_page.url
    return ", ".join(status), landing_url


def run_scan(db_path, scan_id, target_url, config, secrets=None, user_id=None):
    """Run all scan steps. Always ends with the scan marked completed, failed or cancelled."""
    secrets = secrets or {}
    collector = FindingsCollector()
    handler = RequestHandler(target_url, timeout=config["timeout"],
                             max_requests=config["max_requests"], delay=config["delay"],
                             exclude_patterns=config.get("exclude_paths", []),
                             cancel_check=lambda: db.is_cancel_requested(db_path, scan_id))
    modules = config["modules"]
    pages = []
    note = "Finished"

    def progress(percent, step):
        db.update_progress(db_path, scan_id, percent, step, handler.request_count)

    try:
        # Check the target again right before scanning (DNS or ownership could have changed)
        check_target(target_url, user_id=user_id, db_path=db_path)

        # ---- Optional login before crawling
        extra_start_urls = []
        if secrets.get("cookies") or config.get("login_url"):
            progress(1, "Logging in")
            login_status, landing_url = log_in(handler, config, secrets)
            if landing_url:
                extra_start_urls.append(landing_url)
            progress(2, f"Login OK ({login_status})")

        # ---- Step 1: crawl (0% - 40%)
        progress(2, "Crawling the website")
        crawler = Crawler(
            handler, target_url, max_depth=config["max_depth"], max_pages=config["max_pages"],
            extra_start_urls=extra_start_urls,
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
            ("stored_xss", 65, "Testing forms for stored XSS",
             lambda: scan_stored_xss(handler, points, [p["url"] for p in pages], collector)),
            ("sqli", 75, "Testing for SQL injection",
             lambda: scan_sqli(handler, points, collector)),
            ("cmdi", 80, "Testing for command injection",
             lambda: scan_command_injection(handler, points, collector)),
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
            if handler.is_cancelled():
                break
            try:
                action()
            except ScanCancelled:
                break
            except RequestLimitReached:
                note = f"Stopped early: request limit ({config['max_requests']}) reached"
                logger.warning(note)
                break
            start_percent = end_percent

        cancelled = handler.is_cancelled()
        if cancelled:
            note = "Cancelled by the user"
        db.save_findings(db_path, scan_id, collector.sorted_findings())
        db.finish_scan(db_path, scan_id, len(pages), handler.request_count, note=note,
                       cancelled=cancelled)
        logger.info("Scan %s ended (%s) with %d findings", scan_id, note, len(collector.findings))

    except ScanCancelled:  # cancelled while logging in
        db.finish_scan(db_path, scan_id, len(pages), handler.request_count,
                       note="Cancelled by the user", cancelled=True)

    except (TargetError, LoginError) as error:
        db.finish_scan(db_path, scan_id, len(pages), handler.request_count, str(error))
    except Exception as error:  # never leave a scan stuck at "running"
        logger.exception("Scan %s crashed", scan_id)
        db.save_findings(db_path, scan_id, collector.sorted_findings())
        db.finish_scan(db_path, scan_id, len(pages), handler.request_count,
                       f"Unexpected error: {error}")
    finally:
        handler.close()

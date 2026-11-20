"""
Request Handler - the ONLY place in the scanner that sends HTTP requests.

Keeping all requests in one place makes it easy to enforce the safety rules:
  * every URL must be in scope (same host as the target)
  * a timeout on every request
  * a maximum number of requests per scan
  * a small delay between requests so we do not flood the server
  * redirects are never followed automatically (the scanner decides)
"""

import logging
import threading
import time
from urllib.parse import urlparse

import requests

from config import settings
from scanner.target_manager import is_in_scope

logger = logging.getLogger(__name__)


class RequestLimitReached(Exception):
    """Raised when the scan has used up its request budget."""


class ScanCancelled(RequestLimitReached):
    """Raised when the user pressed Cancel. It stops the scan the same way as
    running out of requests, so every module already knows how to handle it."""


class RequestHandler:
    def __init__(self, target_url, timeout=settings.DEFAULT_TIMEOUT,
                 max_requests=settings.DEFAULT_MAX_REQUESTS,
                 delay=settings.DEFAULT_REQUEST_DELAY, exclude_patterns=None):
        self.target_url = target_url
        self.timeout = timeout
        self.max_requests = max_requests
        self.delay = delay
        # Parts of URLs we must never request, e.g. "logout" (would end our login)
        # or "reset" (could wipe the test database)
        self.exclude_patterns = [p.lower() for p in (exclude_patterns or [])]
        self.request_count = 0
        self._lock = threading.Lock()
        # Set by the Cancel button; checked before every request
        self.cancel_event = threading.Event()

        # A Session re-uses connections and keeps cookies between requests
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": settings.USER_AGENT})

    def is_excluded(self, url):
        """Return True if the URL path or query contains an excluded word."""
        parsed = urlparse(url)
        text = (parsed.path + "?" + parsed.query).lower()
        return any(pattern in text for pattern in self.exclude_patterns)

    def send(self, method, url, params=None, data=None):
        """Send one request and return the Response, or None if it failed.

        method: "GET" or "POST"
        params: values for the URL query string (?a=1&b=2)
        data:   form values sent in the body of a POST request
        """
        if not is_in_scope(url, self.target_url):
            logger.warning("Blocked out-of-scope request to %s", url)
            return None
        if self.is_excluded(url):
            logger.info("Skipped excluded URL %s", url)
            return None

        if self.cancel_event.is_set():
            raise ScanCancelled("The scan was cancelled.")

        with self._lock:
            if self.request_count >= self.max_requests:
                raise RequestLimitReached(
                    f"Request limit of {self.max_requests} reached."
                )
            self.request_count += 1

        if self.delay:
            time.sleep(self.delay)

        try:
            response = self.session.request(
                method.upper(),
                url,
                params=params,
                data=data,
                timeout=self.timeout,
                allow_redirects=False,  # never follow redirects automatically
            )
            return response
        except requests.exceptions.Timeout:
            logger.warning("Request timed out: %s %s", method, url)
        except requests.exceptions.ConnectionError:
            logger.warning("Could not connect: %s %s", method, url)
        except requests.exceptions.RequestException as error:
            logger.warning("Request failed: %s %s (%s)", method, url, error)
        return None

    def get(self, url, params=None):
        return self.send("GET", url, params=params)

    def send_payload(self, point, param_name, value):
        """Send a request to an injection point with ONE parameter changed.

        All the other parameters keep their normal values, so the page works
        as usual and only the parameter we are testing is different.
        """
        values = dict(point.params)
        values[param_name] = value
        if point.method == "POST":
            return self.send("POST", point.url, data=values)
        return self.send("GET", point.url, params=values)

    def close(self):
        self.session.close()

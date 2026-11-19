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

import requests

from config import settings
from scanner.target_manager import is_in_scope

logger = logging.getLogger(__name__)


class RequestLimitReached(Exception):
    """Raised when the scan has used up its request budget."""


class RequestHandler:
    def __init__(self, target_url, timeout=settings.DEFAULT_TIMEOUT,
                 max_requests=settings.DEFAULT_MAX_REQUESTS,
                 delay=settings.DEFAULT_REQUEST_DELAY):
        self.target_url = target_url
        self.timeout = timeout
        self.max_requests = max_requests
        self.delay = delay
        self.request_count = 0
        self._lock = threading.Lock()

        # A Session re-uses connections and keeps cookies between requests
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": settings.USER_AGENT})

    def send(self, method, url, params=None, data=None):
        """Send one request and return the Response, or None if it failed.

        method: "GET" or "POST"
        params: values for the URL query string (?a=1&b=2)
        data:   form values sent in the body of a POST request
        """
        if not is_in_scope(url, self.target_url):
            logger.warning("Blocked out-of-scope request to %s", url)
            return None

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

    def close(self):
        self.session.close()

"""
Web Crawler - discovers the pages of the target website.

It works like a breadth-first search (BFS):
  1. Start with the target URL in a queue.
  2. Take a URL from the queue, download it and read its links and forms.
  3. Add new links (same website only) to the queue with depth + 1.
  4. Stop when the queue is empty, max_depth is reached or max_pages is reached.

The crawler only READS pages. It never submits forms - the vulnerability
scanners do that later, in a controlled way.

It also reads the page's JavaScript files as text and picks out strings that
look like paths (e.g. "/api/search?q="), so API endpoints of JavaScript-heavy
sites are found too. It does NOT run the JavaScript.

At the end it returns "injection points": every place where the website
accepts input (URL parameters and form fields). The scanners test those.
"""

import logging
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from scanner.crawler.form_parser import parse_forms
from scanner.crawler.url_parser import (
    extract_js_endpoints, extract_links, extract_script_sources, get_query_params,
    normalize_url, url_without_query,
)
from scanner.engine.request_handler import RequestLimitReached
from scanner.target_manager import is_in_scope

logger = logging.getLogger(__name__)


@dataclass
class InjectionPoint:
    """One place where the website accepts input that we can test."""
    method: str          # "GET" or "POST"
    url: str             # URL without the query string
    params: dict         # every parameter with its normal value
    source: str          # "url" (query string) or "form"
    page_url: str        # page where it was found
    test_params: list = field(default_factory=list)  # which params to test (empty = all)

    def testable_params(self):
        return self.test_params or list(self.params)


@dataclass
class CrawlResult:
    pages: list = field(default_factory=list)            # dicts: url, status_code, depth
    forms: list = field(default_factory=list)            # Form objects
    injection_points: list = field(default_factory=list)
    scripts: list = field(default_factory=list)          # JavaScript files that were read


# Limits for reading JavaScript files, so huge bundles do not slow the scan down
MAX_SCRIPTS = 15
MAX_SCRIPT_BYTES = 3_000_000


class Crawler:
    def __init__(self, request_handler, start_url, max_depth=2, max_pages=30,
                 progress_callback=None, extra_start_urls=None):
        self.request_handler = request_handler
        self.start_url = start_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.progress_callback = progress_callback  # optional: tells the UI how far we are
        # e.g. the page we land on after logging in, which the public pages may not link to
        self.extra_start_urls = [u for u in (extra_start_urls or []) if is_in_scope(u, start_url)]

    def crawl(self):
        result = CrawlResult()
        queue = deque([(self.start_url, 0)])
        seen_urls = {normalize_url(self.start_url)}
        for extra_url in self.extra_start_urls:
            if normalize_url(extra_url) not in seen_urls:
                seen_urls.add(normalize_url(extra_url))
                queue.append((extra_url, 0))
        seen_points = set()
        seen_scripts = set()

        while queue and len(result.pages) < self.max_pages:
            url, depth = queue.popleft()
            try:
                response = self.request_handler.get(url)
            except RequestLimitReached:
                logger.warning("Request limit reached while crawling")
                break
            if response is None:
                continue

            result.pages.append({"url": url, "status_code": response.status_code, "depth": depth})
            if self.progress_callback:
                self.progress_callback(len(result.pages), self.max_pages)

            # Record URL parameters like ?id=1 as an injection point
            params = get_query_params(url)
            if params:
                self._add_point(result, seen_points, InjectionPoint(
                    "GET", url_without_query(url), params, "url", url))

            new_links = []

            # A redirect to another page on the same site is just another link
            if response.is_redirect and "Location" in response.headers:
                new_links.append(urljoin(url, response.headers["Location"]))

            content_type = response.headers.get("Content-Type", "")
            if "html" in content_type.lower():
                soup = BeautifulSoup(response.text, "html.parser")
                new_links.extend(extract_links(soup, url))
                new_links.extend(self._links_from_javascript(soup, url, seen_scripts, result))

                for form in parse_forms(soup, url):
                    if not is_in_scope(form.action, self.start_url):
                        continue
                    result.forms.append(form)
                    if form.text_fields():
                        self._add_point(result, seen_points, InjectionPoint(
                            form.method, url_without_query(form.action),
                            form.default_values(), "form", url,
                            test_params=form.text_fields()))

            if depth >= self.max_depth:
                continue
            for link in new_links:
                if not is_in_scope(link, self.start_url):
                    continue  # never leave the target website
                key = normalize_url(link)
                if key not in seen_urls:
                    seen_urls.add(key)
                    queue.append((link, depth + 1))

        logger.info("Crawl finished: %d pages, %d forms, %d injection points",
                    len(result.pages), len(result.forms), len(result.injection_points))
        return result

    def _links_from_javascript(self, soup, page_url, seen_scripts, result):
        """Read the page's JavaScript (inline and .js files) and pick out URLs.

        Endpoints with parameters (like /api/search?q=) are put first because
        those are the ones the vulnerability scanners can test.
        """
        script_urls, inline_code = extract_script_sources(soup, page_url)
        endpoints = extract_js_endpoints(inline_code, page_url)

        for script_url in script_urls:
            if (script_url in seen_scripts or len(seen_scripts) >= MAX_SCRIPTS
                    or not is_in_scope(script_url, self.start_url)):
                continue
            seen_scripts.add(script_url)
            response = self.request_handler.get(script_url)
            if response is None or response.status_code != 200:
                continue
            if len(response.content) > MAX_SCRIPT_BYTES:
                logger.info("Skipped large script %s (%d bytes)", script_url, len(response.content))
                continue
            result.scripts.append(script_url)
            endpoints.extend(extract_js_endpoints(response.text, page_url))

        endpoints = list(dict.fromkeys(endpoints))
        return sorted(endpoints, key=lambda link: "?" not in link)

    @staticmethod
    def _add_point(result, seen_points, point):
        """Add an injection point unless we already have the same one.

        /product?id=1 and /product?id=2 are the same test, so the key uses
        the parameter NAMES and not their values.
        """
        key = (point.method, point.url, tuple(sorted(point.params)))
        if key not in seen_points:
            seen_points.add(key)
            result.injection_points.append(point)

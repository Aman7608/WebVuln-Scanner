"""
URL Parser - small helper functions for working with links.

  normalize_url()     makes two URLs that mean the same page look identical
  extract_links()     finds every <a href="..."> link in a page
  get_query_params()  reads the ?name=value parameters from a URL
"""

import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

# Files we do not need to crawl because they are not HTML pages
SKIPPED_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".js", ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z",
    ".mp3", ".mp4", ".avi", ".mov", ".woff", ".woff2", ".ttf", ".eot",
    ".exe", ".dmg", ".iso", ".doc", ".docx", ".xls", ".xlsx",
)


def normalize_url(url):
    """Return a clean version of the URL so duplicates can be detected.

    - removes #fragments (they point to the same page)
    - lower-cases the scheme and host
    - sorts the query parameters (?b=2&a=1 is the same as ?a=1&b=2)
    """
    parsed = urlparse(url)
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path or "/",
        "",
        query,
        "",
    ))


def url_without_query(url):
    """http://site/page?a=1 -> http://site/page"""
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))


def get_query_params(url):
    """Return the query parameters as a dict: ?id=1&q=x -> {"id": "1", "q": "x"}"""
    return dict(parse_qsl(urlparse(url).query, keep_blank_values=True))


def is_crawlable_link(url):
    """Skip images, downloads, mailto:, javascript: and similar links."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    return not parsed.path.lower().endswith(SKIPPED_EXTENSIONS)


# Finds strings in JavaScript code that look like paths on the same site,
# for example "/rest/products/search?q=" or '/api/users'.
JS_PATH_PATTERN = re.compile(
    r"""["'`](/[A-Za-z0-9_\-][A-Za-z0-9_\-./]*(?:\?[A-Za-z0-9_\-=&%.]*)?)["'`]""")


def extract_js_endpoints(js_code, page_url):
    """Return full URLs for path-like strings found in JavaScript code.

    The scanner does not RUN JavaScript. It only reads the code as text and
    picks out strings that look like links or API addresses. Single-page apps
    (React, Angular, Vue) keep most of their API addresses in their .js files.
    """
    found = []
    for match in JS_PATH_PATTERN.finditer(js_code):
        path = match.group(1)
        if path.startswith("//") or len(path) < 3:
            continue
        full_url = urljoin(page_url, path)
        if is_crawlable_link(full_url):
            found.append(full_url)
    return list(dict.fromkeys(found))  # remove duplicates, keep order


def extract_script_sources(soup, page_url):
    """Return (list of external script URLs, inline script text)."""
    sources = [urljoin(page_url, tag["src"]) for tag in soup.find_all("script", src=True)]
    inline = "\n".join(tag.string or "" for tag in soup.find_all("script", src=False))
    return sources, inline


def extract_links(soup, page_url):
    """Find all links in a parsed page and turn them into full URLs."""
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith("#"):
            continue
        full_url = urljoin(page_url, href)   # turns "/about" into "http://site/about"
        if is_crawlable_link(full_url):
            links.append(full_url)
    return links

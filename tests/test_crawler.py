"""Tests for the crawler, URL parser and form parser."""

from bs4 import BeautifulSoup

from scanner.crawler.crawler import Crawler
from scanner.crawler.form_parser import parse_forms
from scanner.crawler.url_parser import extract_links, get_query_params, normalize_url


def test_normalize_url_removes_duplicates():
    assert normalize_url("HTTP://Localhost/a?b=2&a=1#top") == normalize_url("http://localhost/a?a=1&b=2")


def test_query_params():
    assert get_query_params("http://x/p?id=5&q=") == {"id": "5", "q": ""}


def test_extract_links_skips_non_pages():
    html = """<a href="/about">a</a><a href="mailto:x@y.z">m</a>
              <a href="javascript:void(0)">j</a><a href="/logo.png">i</a><a href="#top">t</a>"""
    links = extract_links(BeautifulSoup(html, "html.parser"), "http://site/home")
    assert links == ["http://site/about"]


def test_parse_forms_reads_fields():
    html = """<form method="post" action="/login">
        <input name="user" value="bob"><input type="password" name="pw">
        <input type="submit" name="go" value="Go"><textarea name="note">hi</textarea>
        <select name="color"><option value="r">Red</option><option value="b" selected>Blue</option></select>
        <input value="no name"></form>"""
    form = parse_forms(BeautifulSoup(html, "html.parser"), "http://site/page")[0]
    assert form.action == "http://site/login"
    assert form.method == "POST"
    assert form.default_values() == {"user": "bob", "pw": "", "go": "Go", "note": "hi", "color": "b"}
    assert "go" not in form.text_fields()


def test_crawl_lab_finds_pages_forms_and_params(handler, lab_url):
    result = Crawler(handler, lab_url + "/", max_depth=2, max_pages=50).crawl()
    urls = [page["url"] for page in result.pages]

    assert any("/search?q=" in u for u in urls)
    assert any(u.endswith("/login") for u in urls)
    # External and mailto links are never crawled
    assert not any("example.com" in u for u in urls)
    # No duplicate pages
    assert len(urls) == len({normalize_url(u) for u in urls})

    form_actions = {f.action for f in result.forms}
    assert lab_url + "/login" in form_actions

    point_keys = {(p.method, p.url.replace(lab_url, "")) for p in result.injection_points}
    assert ("GET", "/search") in point_keys
    assert ("GET", "/product") in point_keys
    assert ("POST", "/login") in point_keys


def test_crawl_respects_max_depth(handler, lab_url):
    result = Crawler(handler, lab_url + "/", max_depth=1, max_pages=50).crawl()
    urls = [page["url"] for page in result.pages]
    assert any(u.endswith("/about") for u in urls)          # depth 1
    assert not any(u.endswith("/about/team") for u in urls)  # depth 2
    assert max(page["depth"] for page in result.pages) <= 1


def test_crawl_respects_max_pages(handler, lab_url):
    result = Crawler(handler, lab_url + "/", max_depth=5, max_pages=3).crawl()
    assert len(result.pages) == 3


def test_js_endpoint_extraction():
    from scanner.crawler.url_parser import extract_js_endpoints
    code = 'const a = "/api/items?search="; fetch(`/rest/basket`); x = "//cdn.x.com/y"; r = /ab+c/g; img="/logo.png"'
    assert extract_js_endpoints(code, "http://site/") == [
        "http://site/api/items?search=", "http://site/rest/basket"]


def test_js_template_string_endpoints():
    from scanner.crawler.url_parser import extract_js_endpoints
    # This is how Juice Shop (Angular) writes its search API address
    code = "search(t){return this.http.get(`${this.hostServer}/rest/products/search?q=${t}`)}"
    assert extract_js_endpoints(code, "http://site/") == ["http://site/rest/products/search?q="]


def test_crawler_finds_api_hidden_in_javascript(handler, lab_url):
    result = Crawler(handler, lab_url + "/shop", max_depth=1, max_pages=10).crawl()
    assert lab_url + "/static/shop.js" in result.scripts
    assert ("GET", lab_url + "/api/items") in {(p.method, p.url) for p in result.injection_points}

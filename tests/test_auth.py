"""Tests for login support, cookies and excluded paths."""

import pytest

from scanner.crawler.crawler import Crawler
from scanner.engine.auth import LoginError, apply_cookie_string, login_with_form
from scanner.engine.request_handler import RequestHandler
from test_lab.vulnerable_app import LAB_PASSWORD, LAB_USERNAME


@pytest.fixture
def logged_out_handler(lab_url):
    handler = RequestHandler(lab_url, delay=0, exclude_patterns=["logout"])
    yield handler
    handler.close()


def test_cookie_string_is_applied(logged_out_handler):
    assert apply_cookie_string(logged_out_handler, "PHPSESSID=abc123; security=low; junk") == 2
    assert logged_out_handler.session.cookies.get("security") == "low"


def test_login_form_with_csrf_token(logged_out_handler, lab_url):
    login_with_form(logged_out_handler, lab_url + "/account/login", LAB_USERNAME, LAB_PASSWORD)
    page = logged_out_handler.get(lab_url + "/account/home")
    assert page.status_code == 200 and "Welcome back" in page.text


def test_wrong_password_is_reported(logged_out_handler, lab_url):
    with pytest.raises(LoginError, match="still shown"):
        login_with_form(logged_out_handler, lab_url + "/account/login", LAB_USERNAME, "wrong")


def test_page_without_login_form(logged_out_handler, lab_url):
    with pytest.raises(LoginError, match="No form with a password field"):
        login_with_form(logged_out_handler, lab_url + "/about", "x", "y")


def test_excluded_urls_are_never_requested(logged_out_handler, lab_url):
    assert logged_out_handler.get(lab_url + "/account/logout") is None
    assert logged_out_handler.request_count == 0


def test_crawler_finds_member_pages_only_after_login(logged_out_handler, lab_url):
    def crawl_urls():
        result = Crawler(logged_out_handler, lab_url + "/account/home", max_depth=2, max_pages=20).crawl()
        return [page["url"] for page in result.pages]

    assert not any("/account/notes" in url for url in crawl_urls())

    login_with_form(logged_out_handler, lab_url + "/account/login", LAB_USERNAME, LAB_PASSWORD)
    urls = crawl_urls()
    assert any("/account/notes" in url for url in urls)
    # The logout link was skipped, so we are still logged in at the end
    assert not any("logout" in url for url in urls)
    assert "Welcome back" in logged_out_handler.get(lab_url + "/account/home").text

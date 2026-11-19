"""
Authentication - lets the scanner test pages that are behind a login.

Two ways to log in (you can use one or both):

1. Session cookie
   Log in with your own browser, copy the cookie (for example
   "PHPSESSID=abc123; security=low") and paste it in the scan form.

2. Login form
   Give the URL of the login page plus a TEST username and password.
   The scanner opens the page, finds the form that has a password field,
   keeps all hidden fields (many sites use a hidden "CSRF token" there),
   fills in the username and password, and submits it.
   Afterwards it checks that the password field is gone - if the login
   form is still shown, the login failed.

The password and cookie are only kept in memory while the scan runs.
They are NEVER saved in the database or the reports.
"""

import logging
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from scanner.crawler.form_parser import parse_forms

logger = logging.getLogger(__name__)

USERNAME_FIELD_TYPES = ("text", "email")


class LoginError(Exception):
    """Raised when the scanner could not log in."""


def apply_cookie_string(handler, cookie_string):
    """Add cookies like "a=1; b=2" to the scanner's session."""
    count = 0
    for part in (cookie_string or "").split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        if name.strip():
            handler.session.cookies.set(name.strip(), value.strip())
            count += 1
    return count


def follow_redirects(handler, response, max_hops=5):
    """Follow redirects ourselves (the handler never does it automatically)."""
    hops = 0
    while response is not None and response.is_redirect and hops < max_hops:
        next_url = urljoin(response.url, response.headers.get("Location", ""))
        response = handler.get(next_url)
        hops += 1
    return response


def find_login_form(html, page_url):
    """Return the first form on the page that has a password field."""
    for form in parse_forms(BeautifulSoup(html, "html.parser"), page_url):
        if any(f.field_type == "password" for f in form.fields):
            return form
    return None


def page_has_password_field(html):
    soup = BeautifulSoup(html or "", "html.parser")
    return soup.find("input", attrs={"type": "password"}) is not None


def login_with_form(handler, login_url, username, password):
    """Log in through an HTML login form. Raises LoginError if it fails."""
    page = follow_redirects(handler, handler.get(login_url))
    if page is None:
        raise LoginError(f"Could not open the login page {login_url}.")

    form = find_login_form(page.text, page.url)
    if form is None:
        raise LoginError("No form with a password field was found on the login page.")

    values = form.default_values()   # keeps hidden fields such as CSRF tokens
    password_field = next(f.name for f in form.fields if f.field_type == "password")
    username_field = next((f.name for f in form.fields if f.field_type in USERNAME_FIELD_TYPES), None)
    if username_field is None:
        raise LoginError("The login form has no username field.")
    values[username_field] = username
    values[password_field] = password

    if form.method == "POST":
        response = handler.send("POST", form.action, data=values)
    else:
        response = handler.send("GET", form.action, params=values)
    response = follow_redirects(handler, response)
    if response is None:
        raise LoginError("The login request failed.")

    # Still seeing a password box means we are still on the login page
    if page_has_password_field(response.text):
        raise LoginError("Login failed: the login form is still shown. Check the username and password.")

    logger.info("Logged in as %s via %s", username, login_url)
    return response

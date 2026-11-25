"""
Test Lab - a small, DELIBERATELY VULNERABLE website for testing the scanner.

!!! Never deploy this anywhere. It only listens on 127.0.0.1 (your own PC). !!!

Every vulnerable page has a "safe" twin that does the same job correctly.
This lets us check two things:
  * the scanner FINDS the real bugs
  * the scanner does NOT report the safe pages (no false positives)

Run it on its own with:
    python -m test_lab.vulnerable_app
and it will be available at http://127.0.0.1:5001
"""

import ipaddress
import json
import re
import sqlite3
import threading
import time
from html import escape
from urllib.parse import urlparse

from flask import Flask, Response, redirect, request, session

lab = Flask(__name__)
# Fixed key is fine here: this lab is a local test toy, never a real app
lab.secret_key = "test-lab-only-not-secret"

# Test account for the login-protected area (used by the tests and the demo)
LAB_USERNAME = "tester"
LAB_PASSWORD = "lab-password"


def sqlite_sleep(seconds):
    """Lets the lab's SQLite understand SLEEP(n) like MySQL does (max 5 s)."""
    time.sleep(min(float(seconds), 5))
    return 0


def make_database():
    """Create a tiny in-memory database with fake products and users."""
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.create_function("SLEEP", 1, sqlite_sleep)
    connection.executescript(
        """
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        INSERT INTO products VALUES (1, 'Laptop', 899.0), (2, 'Mouse', 19.5),
                                    (3, 'Keyboard', 49.9);
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        INSERT INTO users VALUES (1, 'admin', 'not-a-real-password');
        CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT);
        INSERT INTO orders VALUES (1, 'shipped'), (2, 'packing');
        """
    )
    return connection


DATABASE = make_database()
DATABASE_LOCK = threading.Lock()   # one query at a time on the shared connection
GUESTBOOK = []                     # stored guestbook entries (kept in memory)


def page(title, body):
    return f"""<!doctype html>
<html><head><title>{title} - Test Lab</title></head>
<body><h1>{title}</h1>{body}
<p><a href="/">Back to home</a></p></body></html>"""


@lab.route("/")
def home():
    return page("Vulnerable Test Lab", """
<ul>
  <li><a href="/search?q=laptop">Search (vulnerable XSS)</a></li>
  <li><a href="/safe-search?q=laptop">Search (safe)</a></li>
  <li><a href="/profile?name=guest">Profile (XSS inside attribute)</a></li>
  <li><a href="/product?id=1">Product (vulnerable SQL injection)</a></li>
  <li><a href="/product-safe?id=1">Product (safe)</a></li>
  <li><a href="/goto?url=/about">Go to (open redirect)</a></li>
  <li><a href="/safe-goto?next=/about">Go to (safe redirect)</a></li>
  <li><a href="/login">Login form</a></li>
  <li><a href="/contact">Contact form</a></li>
  <li><a href="/about">About</a></li>
  <li><a href="/order?id=1">Order status (blind SQL injection)</a></li>
  <li><a href="/guestbook">Guestbook (stored XSS)</a></li>
  <li><a href="/account/login">Member area (needs login)</a></li>
  <li><a href="/shop">Shop (JavaScript app)</a></li>
  <li><a href="/ping?host=127.0.0.1">Ping tool (command injection)</a></li>
  <li><a href="/ping-safe?host=127.0.0.1">Ping tool (safe)</a></li>
  <li><a href="https://example.com/external">External link (must not be crawled)</a></li>
  <li><a href="mailto:test@example.com">Email link</a></li>
</ul>""")


@lab.route("/about")
def about():
    return page("About", "<p>This lab helps test WebVuln Scanner.</p>"
                         '<p><a href="/about/team">Team</a></p>')


@lab.route("/about/team")
def team():
    return page("Team", '<p>Deep page.</p><p><a href="/about/team/history">History</a></p>')


@lab.route("/about/team/history")
def history():
    return page("History", "<p>Even deeper page.</p>")


# ---------------- XSS ----------------
@lab.route("/search")
def search():
    query = request.args.get("q", "")
    # BUG: user input is put into the HTML without escaping
    return page("Search", f"<p>You searched for: {query}</p>")


@lab.route("/safe-search")
def safe_search():
    query = request.args.get("q", "")
    # SAFE: escape() turns < > " ' into harmless HTML entities
    return page("Safe Search", f"<p>You searched for: {escape(query)}</p>")


@lab.route("/profile")
def profile():
    name = request.args.get("name", "")
    # BUG: input lands inside an attribute value without escaping quotes
    return page("Profile", f'<form><input type="text" name="display" value="{name}"></form>')


# ---------------- SQL injection ----------------
@lab.route("/product")
def product():
    product_id = request.args.get("id", "1")
    # BUG: string concatenation builds the SQL query
    sql = f"SELECT name, price FROM products WHERE id = {product_id}"
    try:
        rows = DATABASE.execute(sql).fetchall()
    except sqlite3.Error as error:
        # BUG: the database error is shown to the user
        return page("Product", f"<p>Database error: sqlite3.OperationalError: {escape(str(error))}</p>"), 500
    if not rows:
        return page("Product", "<p>No product found.</p>")
    items = "".join(f"<li>{escape(name)} - ${price}</li>" for name, price in rows)
    return page("Product", f"<ul>{items}</ul>")


@lab.route("/product-safe")
def product_safe():
    product_id = request.args.get("id", "1")
    # SAFE: the ? placeholder keeps data and SQL code separate
    rows = DATABASE.execute(
        "SELECT name, price FROM products WHERE id = ?", (product_id,)
    ).fetchall()
    if not rows:
        return page("Product", "<p>No product found.</p>")
    items = "".join(f"<li>{escape(name)} - ${price}</li>" for name, price in rows)
    return page("Product", f"<ul>{items}</ul>")


@lab.route("/login", methods=["GET", "POST"])
def login():
    form = """
<form method="post" action="/login">
  <input type="text" name="username" value="">
  <input type="password" name="password" value="">
  <input type="submit" value="Log in">
</form>"""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # BUG: string concatenation with quotes -> SQL injection
        sql = (f"SELECT id FROM users WHERE username = '{username}' "
               f"AND password = '{password}'")
        try:
            user = DATABASE.execute(sql).fetchone()
        except sqlite3.Error as error:
            return page("Login", f"<p>SQL error: {escape(str(error))}</p>" + form), 500
        message = "Welcome back!" if user else "Wrong username or password."
        return page("Login", f"<p>{message}</p>" + form)
    return page("Login", form)


# ---------------- Open redirect ----------------
@lab.route("/goto")
def goto():
    # BUG: redirects to ANY url given in the parameter
    return redirect(request.args.get("url", "/"))


@lab.route("/safe-goto")
def safe_goto():
    target = request.args.get("next", "/")
    # SAFE: only allow paths on this same site
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        target = "/"
    return redirect(target)


# ---------------- Form with a safe POST handler ----------------
@lab.route("/contact", methods=["GET", "POST"])
def contact():
    form = """
<form method="post">
  <input type="text" name="email" value="">
  <textarea name="message"></textarea>
  <select name="topic"><option value="general">General</option><option value="sales">Sales</option></select>
  <input type="submit" value="Send">
</form>"""
    if request.method == "POST":
        return page("Contact", f"<p>Thanks {escape(request.form.get('email', ''))}!</p>" + form)
    return page("Contact", form)


# ---------------- Blind (time-based) SQL injection ----------------
@lab.route("/order")
def order():
    order_id = request.args.get("id", "1")
    # BUG: string concatenation, but errors and results are hidden (blind)
    sql = f"SELECT status FROM orders WHERE id = {order_id}"
    try:
        with DATABASE_LOCK:
            DATABASE.execute(sql).fetchall()
    except sqlite3.Error:
        pass
    # The page is always the same, so only timing can reveal the bug
    return page("Order status", "<p>Thank you. Your order status has been checked.</p>")


# ---------------- Stored XSS ----------------
@lab.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    if request.method == "POST":
        if "clear" in request.form:
            GUESTBOOK.clear()   # like DVWA's "Clear Guestbook" button
        elif "sign" in request.form:
            GUESTBOOK.append((request.form.get("name", ""), request.form.get("message", "")))
            del GUESTBOOK[:-50]  # keep only the last 50 entries
        return redirect("/guestbook")
    # BUG: saved entries are shown without escaping
    entries = "".join(f"<li><b>{name}</b>: {message}</li>" for name, message in GUESTBOOK)
    return page("Guestbook", f"""<ul>{entries}</ul>
<form method="post">
  <input type="text" name="name" value="">
  <textarea name="message"></textarea>
  <input type="submit" name="sign" value="Sign">
  <input type="submit" name="clear" value="Clear guestbook">
</form>""")


# ---------------- Area behind a login ----------------
@lab.route("/account/login", methods=["GET", "POST"])
def account_login():
    error = ""
    if request.method == "POST":
        # Hidden CSRF token, like many real login forms have
        if request.form.get("csrf_token") != session.get("csrf_token"):
            error = "<p>Invalid form token.</p>"
        elif (request.form.get("user") == LAB_USERNAME
              and request.form.get("pass") == LAB_PASSWORD):
            session["user"] = LAB_USERNAME
            return redirect("/account/home")
        else:
            error = "<p>Wrong username or password.</p>"
    session["csrf_token"] = str(time.time_ns())
    return page("Member login", f"""{error}
<form method="post">
  <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
  <input type="text" name="user" value="">
  <input type="password" name="pass" value="">
  <input type="submit" value="Log in">
</form>""")


@lab.route("/account/home")
def account_home():
    if session.get("user") != LAB_USERNAME:
        return redirect("/account/login")
    return page("Member area", """
<p>Welcome back!</p>
<p><a href="/account/notes?title=todo">My notes</a></p>
<p><a href="/account/logout">Log out</a></p>""")


@lab.route("/account/notes")
def account_notes():
    if session.get("user") != LAB_USERNAME:
        return redirect("/account/login")
    # BUG: reflected XSS that can only be found after logging in
    return page("Notes", f"<p>Showing notes for: {request.args.get('title', '')}</p>")


@lab.route("/account/logout")
def account_logout():
    session.clear()
    return redirect("/")


# ---------------- JavaScript app with a hidden API ----------------
@lab.route("/shop")
def shop():
    # The page itself has no links - only the JavaScript knows the API address
    return page("Shop", '<div id="app">Loading...</div><script src="/static/shop.js"></script>')


@lab.route("/static/shop.js")
def shop_js():
    code = """
const API = "/api/items?search=";
fetch(API + "lamp").then(r => r.json()).then(items => {
  document.getElementById("app").textContent = items.length + " items";
});
"""
    return Response(code, mimetype="application/javascript")


@lab.route("/api/items")
def api_items():
    term = request.args.get("search", "")
    # BUG: SQL injection in a JSON API (like many single-page apps have)
    sql = f"SELECT name FROM products WHERE name LIKE '%{term}%'"
    try:
        with DATABASE_LOCK:
            rows = DATABASE.execute(sql).fetchall()
    except sqlite3.Error as error:
        return Response(json.dumps({"error": f"SQLITE_ERROR: {error}"}), status=500,
                        mimetype="application/json")
    return Response(json.dumps([name for (name,) in rows]), mimetype="application/json")


# ---------------- Command injection (simulated) ----------------
SHELL_SLEEP = re.compile(r"(?:;|\|\|?|&&|\$\()\s*sleep\s+(\d+(?:\.\d+)?)")


@lab.route("/ping")
def ping_tool():
    host = request.args.get("host", "")
    # BUG (simulated): a real app would run  os.system("ping -c 1 " + host)
    # The lab does NOT run a shell. It only copies what a shell would do with
    # "; sleep N", so the scanner can be tested without any real danger.
    match = SHELL_SLEEP.search(host)
    if match:
        time.sleep(min(float(match.group(1)), 5))
    return page("Ping tool", f"<p>Ping sent to {escape(host)}.</p>")


@lab.route("/ping-safe")
def ping_tool_safe():
    host = request.args.get("host", "")
    # SAFE: only accept a real IP address, never pass text to a shell
    try:
        ipaddress.ip_address(host)
        result = f"Ping sent to {escape(host)}."
    except ValueError:
        result = "Please enter a valid IP address."
    return page("Ping tool", f"<p>{result}</p>")


# ---------------- Exposed files ----------------
@lab.route("/.env")
def dotenv():
    # Fake secrets, only for testing directory discovery
    return Response("APP_ENV=lab\nSECRET_KEY=fake-lab-secret\nDB_PASSWORD=fake\n",
                    mimetype="text/plain")


@lab.route("/backup/")
def backup():
    return page("Index of /backup", '<pre><a href="site.zip">site.zip</a></pre>')


VERIFY_TOKEN = {"value": ""}   # tests put an ownership code here


@lab.route("/.well-known/webvuln-verify.txt")
def ownership_file():
    # Lets the tests check "prove you own this site" against the lab
    if not VERIFY_TOKEN["value"]:
        return Response("not found", status=404)
    return Response(VERIFY_TOKEN["value"], mimetype="text/plain")


@lab.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /backup/\n", mimetype="text/plain")


def run_lab(port=5001):
    print(f"Vulnerable test lab running at http://127.0.0.1:{port} (do not expose it!)")
    # threaded=False: one request at a time, so the shared SQLite connection is safe
    lab.run(host="127.0.0.1", port=port, debug=False, threaded=False)


if __name__ == "__main__":
    run_lab()

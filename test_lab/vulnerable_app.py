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

import sqlite3
from html import escape
from urllib.parse import urlparse

from flask import Flask, Response, redirect, request

lab = Flask(__name__)


def make_database():
    """Create a tiny in-memory database with fake products and users."""
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.executescript(
        """
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        INSERT INTO products VALUES (1, 'Laptop', 899.0), (2, 'Mouse', 19.5),
                                    (3, 'Keyboard', 49.9);
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        INSERT INTO users VALUES (1, 'admin', 'not-a-real-password');
        """
    )
    return connection


DATABASE = make_database()


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


# ---------------- Exposed files ----------------
@lab.route("/.env")
def dotenv():
    # Fake secrets, only for testing directory discovery
    return Response("APP_ENV=lab\nSECRET_KEY=fake-lab-secret\nDB_PASSWORD=fake\n",
                    mimetype="text/plain")


@lab.route("/backup/")
def backup():
    return page("Index of /backup", '<pre><a href="site.zip">site.zip</a></pre>')


@lab.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /backup/\n", mimetype="text/plain")


def run_lab(port=5001):
    print(f"Vulnerable test lab running at http://127.0.0.1:{port} (do not expose it!)")
    lab.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    run_lab()

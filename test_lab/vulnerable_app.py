"""
Test Lab - a small, DELIBERATELY VULNERABLE website for testing the scanner.

!!! Never deploy this anywhere. It only listens on 127.0.0.1 (your own PC). !!!

Every vulnerable page has a "safe" twin that does the same job correctly.
This lets us check two things:
  * the scanner FINDS the real bugs
  * the scanner does NOT report the safe pages (no false positives)

The pages also explain themselves ("What is going on here?"), so you can
learn by trying the bugs by hand. They work on phones, tablets and laptops.

Run it on its own with:
    python -m test_lab.vulnerable_app
and it will be available at http://127.0.0.1:5001

Notes for whoever edits this file:
  * Keep the styling in lab.css (a separate file). The SQL injection check
    compares the first part of pages, and a big <style> block at the top would
    make every page look the same.
  * Never write database error messages in the explanation texts. The scanner
    skips pages that already show an SQL error, so the SQLi checks would stop
    working.
"""

import ipaddress
import json
import os
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

LAB_DIR = os.path.dirname(os.path.abspath(__file__))

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

PRODUCT_DETAILS = {
    "Laptop": "A 14 inch ultrabook with a backlit keyboard, 16 GB of memory and an all-day battery. "
              "Weighs 1.3 kg and charges over USB-C.",
    "Mouse": "A small wireless mouse with silent buttons and a scroll wheel that clicks. "
             "Runs for months on one AA battery.",
    "Keyboard": "A compact mechanical keyboard with brown switches, white lights and a "
                "detachable braided cable.",
}


# ------------------------------------------------------------------ layout
def lesson_panel(lesson):
    """The "What is going on here?" box shown under each test page."""
    if not lesson:
        return ""
    parts = [f"<dt>The bug</dt><dd>{lesson['bug']}</dd>"]
    if lesson.get("try"):
        parts.append(
            f"<dt>Try it yourself</dt><dd><div class=\"copy-row\"><code>{escape(lesson['try'])}</code>"
            f"<button type=\"button\" class=\"button-ghost button-small\" data-copy=\"{escape(lesson['try'])}\">"
            f"Copy</button></div>{lesson.get('try_note', '')}</dd>")
    parts.append(f"<dt>How it is fixed</dt><dd>{lesson['fix']}</dd>")
    if lesson.get("twin"):
        href, label = lesson["twin"]
        parts.append(f"<dt>Compare</dt><dd><a href=\"{href}\">{label}</a></dd>")
    return (f"<details class=\"card lesson\"><summary>What is going on here?</summary>"
            f"<dl>{''.join(parts)}</dl></details>")


def page(title, body, kind=None, lesson=None):
    """Wrap a page body in the shared layout.

    kind: "vulnerable", "safe" or "info" - shown as a coloured badge.
    """
    badge = f'<span class="badge badge-{kind}">{kind}</span>' if kind else ""
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - Test Lab</title>
<link rel="stylesheet" href="/assets/lab.css">
</head><body>
<header class="topbar"><div class="topbar-inner">
  <a class="logo" href="/"><span class="logo-mark"></span>WebVuln Test Lab</a>
  <span class="warning-pill">Deliberately vulnerable - local use only</span>
</div></header>
<main class="container">
<div class="page-head"><h1>{title}</h1>{badge}</div>
{body}
{lesson_panel(lesson)}
<p><a href="/">Back to home</a></p>
</main>
<footer class="footer">Practice target for WebVuln Scanner. Never put this lab on the internet.</footer>
<script src="/assets/lab.js"></script>
</body></html>"""


def search_form(action, name, label, placeholder, button="Go"):
    """A small GET form so people can type their own input on a test page."""
    return f"""<form class="form" method="get" action="{action}">
  <label>{label}
    <span class="form-row"><input type="text" name="{name}" value="" placeholder="{placeholder}">
    <input type="submit" value="{button}"></span>
  </label>
</form>"""


@lab.route("/assets/lab.css")
def lab_css():
    with open(os.path.join(LAB_DIR, "lab.css"), encoding="utf-8") as file:
        return Response(file.read(), mimetype="text/css")


@lab.route("/assets/lab.js")
def lab_js():
    with open(os.path.join(LAB_DIR, "lab.js"), encoding="utf-8") as file:
        return Response(file.read(), mimetype="application/javascript")


# ------------------------------------------------------------------ home page
CARDS = [
    # (group, title, link, kind, description, payload to try)
    ("XSS", "Search", "/search?q=laptop", "vulnerable",
     "Shows your search word back on the page without escaping it.", "<b>hello</b>"),
    ("XSS", "Safe search", "/safe-search?q=laptop", "safe",
     "The same search, but the word is escaped first.", "<b>hello</b>"),
    ("XSS", "Profile", "/profile?name=guest", "vulnerable",
     "Puts your name inside an HTML attribute - a quote breaks out of it.", 'guest" style="color:red'),
    ("XSS", "Guestbook", "/guestbook", "vulnerable",
     "Saves messages and shows them to every visitor (stored XSS).", "<i>hi from the guestbook</i>"),
    ("SQL injection", "Product", "/product?id=1", "vulnerable",
     "Builds the database query by joining text. A quote breaks it.", "1'"),
    ("SQL injection", "Safe product", "/product-safe?id=1", "safe",
     "The same lookup with a parameterized query.", "1'"),
    ("SQL injection", "Login form", "/login", "vulnerable",
     "A login that glues the username into SQL. Try a quote as the username.", "' OR '1'='1"),
    ("SQL injection", "Order status", "/order?id=1", "vulnerable",
     "Blind SQL injection: the page never changes, only the time it takes.", "1 AND SLEEP(3)"),
    ("Command injection", "Ping tool", "/ping?host=127.0.0.1", "vulnerable",
     "Pretends to pass your input to a shell command (nothing really runs).", "127.0.0.1;sleep 3"),
    ("Command injection", "Safe ping tool", "/ping-safe?host=127.0.0.1", "safe",
     "Only accepts a real IP address.", "127.0.0.1;sleep 3"),
    ("Open redirect", "Go to", "/goto?url=/about", "vulnerable",
     "Sends you to ANY address in the url parameter.", "https://example.com"),
    ("Open redirect", "Safe go to", "/safe-goto?next=/about", "safe",
     "Only allows paths on this same site.", "https://example.com"),
    ("Login", "Member area", "/account/login", "info",
     "A login page with a hidden token. The test account is shown on the page. Behind it is a hidden XSS bug.", None),
    ("JavaScript", "Shop app", "/shop", "info",
     "The page has no links - its API address is only inside a JavaScript file.", None),
    ("Forms", "Contact form", "/contact", "safe",
     "A form that escapes what you type. Should give no findings.", "<b>hello</b>"),
    ("Pages", "About", "/about", "info",
     "Normal pages a few clicks deep, to test the crawler's depth limit.", None),
]


def card_html(group, title, href, kind, text, payload):
    hint = ""
    if payload:
        hint = (f'<details class="hint"><summary>Hint</summary><div class="hint-body">'
                f'<span>Type this into the page:</span><div class="copy-row"><code>{escape(payload)}</code>'
                f'<button type="button" class="button-ghost button-small" data-copy="{escape(payload)}">Copy</button>'
                f'</div></div></details>')
    return f"""<article class="card lab-card" data-kind="{kind}">
  <div class="card-top"><span class="tag">{group}</span><span class="badge badge-{kind}">{kind}</span></div>
  <h3>{title}</h3>
  <p>{text}</p>
  <div class="card-actions"><a class="button button-small" href="{href}">Open</a>{hint}</div>
</article>"""


@lab.route("/")
def home():
    cards = "".join(card_html(*card) for card in CARDS)
    vulnerable = sum(1 for card in CARDS if card[3] == "vulnerable")
    safe = sum(1 for card in CARDS if card[3] == "safe")
    return page("Vulnerable Test Lab", f"""
<section class="hero">
  <p>A practice website full of <strong>known</strong> security bugs. Point WebVuln Scanner at
     <code>http://127.0.0.1:5001/</code> and see if it finds them all, or open a page and try the bug by hand.
     Every bug has a <strong>safe twin</strong> that must <em>not</em> be reported.</p>
  <div class="stats">
    <span class="stat"><strong>{vulnerable}</strong>vulnerable</span>
    <span class="stat"><strong>{safe}</strong>safe twins</span>
    <span class="stat"><strong>{len(CARDS)}</strong>pages in total</span>
  </div>
</section>

<div class="toolbar">
  <input type="search" id="lab-search" placeholder="Search pages... (press / )" aria-label="Search pages">
  <div class="chips">
    <button type="button" class="chip active" data-filter="all">All</button>
    <button type="button" class="chip" data-filter="vulnerable">Vulnerable</button>
    <button type="button" class="chip" data-filter="safe">Safe</button>
    <button type="button" class="chip" data-filter="info">Other</button>
  </div>
  <span class="tag" id="lab-count"></span>
</div>

<section class="grid">{cards}</section>
<p class="empty-note" id="lab-empty" hidden>No page matches your search.</p>

<section class="card">
  <h2>Edge cases for the crawler</h2>
  <p>The scanner must <strong>not</strong> follow these:</p>
  <ul>
    <li><a href="https://example.com/external">External link (must not be crawled)</a></li>
    <li><a href="mailto:test@example.com">Email link</a></li>
  </ul>
</section>""")


@lab.route("/about")
def about():
    return page("About", '<div class="card"><p>This lab helps test WebVuln Scanner. The pages below are '
                         'a few clicks deep, so you can test the crawler\'s depth limit.</p>'
                         '<p><a href="/about/team">Team</a></p></div>', kind="info")


@lab.route("/about/team")
def team():
    return page("Team", '<div class="card"><p>Deep page (2 clicks from home).</p>'
                        '<p><a href="/about/team/history">History</a></p></div>', kind="info")


@lab.route("/about/team/history")
def history():
    return page("History", '<div class="card"><p>Even deeper page (3 clicks from home).</p></div>', kind="info")


# ---------------- XSS ----------------
@lab.route("/search")
def search():
    query = request.args.get("q", "")
    # BUG: user input is put into the HTML without escaping
    return page("Search", f"""<div class="card">
<p class="result">You searched for: {query}</p>
{search_form("/search", "q", "Search again", "laptop", "Search")}
</div>""", kind="vulnerable", lesson={
        "bug": "Your search word is written straight into the HTML. If you type HTML tags, the browser runs them.",
        "try": "<b>hello</b>",
        "try_note": " - the word turns <strong>bold</strong>, so tags get through. A real attacker would use a script tag.",
        "fix": "Escape the text before putting it in the page, so <code>&lt;</code> and <code>&gt;</code> become harmless.",
        "twin": ("/safe-search?q=laptop", "Open the safe search"),
    })


@lab.route("/safe-search")
def safe_search():
    query = request.args.get("q", "")
    # SAFE: escape() turns < > " ' into harmless HTML entities
    return page("Safe Search", f"""<div class="card">
<p class="result">You searched for: {escape(query)}</p>
{search_form("/safe-search", "q", "Search again", "laptop", "Search")}
</div>""", kind="safe", lesson={
        "bug": "None. This page escapes your word with html.escape() before showing it.",
        "try": "<b>hello</b>",
        "try_note": " - you will see the tags as plain text instead of bold text.",
        "fix": "This is the fixed version of the Search page.",
        "twin": ("/search?q=laptop", "Open the vulnerable search"),
    })


@lab.route("/profile")
def profile():
    name = request.args.get("name", "")
    # BUG: input lands inside an attribute value without escaping quotes
    return page("Profile", f"""<div class="card">
<form class="form"><label>Display name <input type="text" name="display" value="{name}"></label></form>
{search_form("/profile", "name", "Change your name", "guest", "Save")}
</div>""", kind="vulnerable", lesson={
        "bug": "Your name is put inside <code>value=\"...\"</code> without escaping the quote character, "
               "so a quote ends the attribute and anything after it becomes new HTML.",
        "try": 'guest" style="color:red',
        "try_note": " - the name box turns red: you just added your own attribute.",
        "fix": "Escape quotes too (html.escape does this) or use a template engine that does it for you.",
    })


# ---------------- SQL injection ----------------
def product_list(rows):
    items = "".join(
        f'<li><strong>{escape(name)}</strong> <span class="price">${price}</span>'
        f'<br><span>{escape(PRODUCT_DETAILS.get(name, ""))}</span></li>'
        for name, price in rows)
    return f'<ul class="items">{items}</ul>'


PRODUCT_LESSON = {
    "bug": "The page builds its database query by joining your text into it: "
           "<code>... WHERE id = </code> + id. Extra characters change the query itself.",
    "try": "1'",
    "try_note": " - the quote breaks the query and the page shows the database's own error message.",
    "fix": "Use a parameterized query: <code>WHERE id = ?</code> and pass the value separately.",
    "twin": ("/product-safe?id=1", "Open the safe product page"),
}


@lab.route("/product")
def product():
    product_id = request.args.get("id", "1")
    # BUG: string concatenation builds the SQL query
    sql = f"SELECT name, price FROM products WHERE id = {product_id}"
    form = search_form("/product", "id", "Product number", "1, 2 or 3", "Show")
    try:
        rows = DATABASE.execute(sql).fetchall()
    except sqlite3.Error as error:
        # BUG: the database error is shown to the user
        return page("Product", f'<div class="card"><div class="alert alert-bad">Database error: '
                               f'sqlite3.OperationalError: {escape(str(error))}</div>{form}</div>',
                    kind="vulnerable", lesson=PRODUCT_LESSON), 500
    if not rows:
        return page("Product", f'<div class="card"><p>No product found.</p>{form}</div>',
                    kind="vulnerable", lesson=PRODUCT_LESSON)
    return page("Product", f'<div class="card">{product_list(rows)}{form}</div>',
                kind="vulnerable", lesson=PRODUCT_LESSON)


@lab.route("/product-safe")
def product_safe():
    product_id = request.args.get("id", "1")
    # SAFE: the ? placeholder keeps data and SQL code separate
    rows = DATABASE.execute(
        "SELECT name, price FROM products WHERE id = ?", (product_id,)
    ).fetchall()
    form = search_form("/product-safe", "id", "Product number", "1, 2 or 3", "Show")
    lesson = {
        "bug": "None. The value is sent separately from the query, so it can never change the SQL.",
        "try": "1'",
        "try_note": " - you just get \"No product found\".",
        "fix": "This is the fixed version of the Product page.",
        "twin": ("/product?id=1", "Open the vulnerable product page"),
    }
    if not rows:
        return page("Product", f'<div class="card"><p>No product found.</p>{form}</div>',
                    kind="safe", lesson=lesson)
    return page("Product", f'<div class="card">{product_list(rows)}{form}</div>', kind="safe", lesson=lesson)


LOGIN_FORM = """
<form class="form" method="post" action="/login">
  <label>Username <input type="text" name="username" value="" autocomplete="off"></label>
  <label>Password <input type="password" name="password" value=""></label>
  <input type="submit" value="Log in">
</form>"""

LOGIN_LESSON = {
    "bug": "The username and password are glued into the SQL text with quotes around them, "
           "so a quote in the username ends the text early and changes the query.",
    "try": "' OR '1'='1",
    "try_note": " - type it as the username and as the password: you are logged in without knowing any password.",
    "fix": "Use a parameterized query, store passwords as hashes and never show database errors to users.",
}


@lab.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # BUG: string concatenation with quotes -> SQL injection
        sql = (f"SELECT id FROM users WHERE username = '{username}' "
               f"AND password = '{password}'")
        try:
            user = DATABASE.execute(sql).fetchone()
        except sqlite3.Error as error:
            return page("Login", f'<div class="card"><div class="alert alert-bad">SQL error: '
                                 f'{escape(str(error))}</div>{LOGIN_FORM}</div>',
                        kind="vulnerable", lesson=LOGIN_LESSON), 500
        message = ('<div class="alert alert-good">Welcome back!</div>' if user
                   else '<div class="alert alert-bad">Wrong username or password.</div>')
        return page("Login", f'<div class="card">{message}{LOGIN_FORM}</div>',
                    kind="vulnerable", lesson=LOGIN_LESSON)
    return page("Login", f'<div class="card">{LOGIN_FORM}</div>', kind="vulnerable", lesson=LOGIN_LESSON)


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
CONTACT_FORM = """
<form class="form" method="post">
  <label>Your email <input type="text" name="email" value="" placeholder="you@example.com"></label>
  <label>Message <textarea name="message"></textarea></label>
  <label>Topic <select name="topic"><option value="general">General</option><option value="sales">Sales</option></select></label>
  <input type="submit" value="Send">
</form>"""


@lab.route("/contact", methods=["GET", "POST"])
def contact():
    lesson = {
        "bug": "None. What you type is escaped before it is shown.",
        "try": "<b>hello</b>",
        "try_note": " - as your email: the thank-you message shows the tags as text.",
        "fix": "This page is the safe example. The scanner should report nothing here.",
    }
    if request.method == "POST":
        thanks = f'<div class="alert alert-good">Thanks {escape(request.form.get("email", ""))}!</div>'
        return page("Contact", f'<div class="card">{thanks}{CONTACT_FORM}</div>', kind="safe", lesson=lesson)
    return page("Contact", f'<div class="card">{CONTACT_FORM}</div>', kind="safe", lesson=lesson)


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
    return page("Order status", f"""<div class="card">
<p class="result">Thank you. Your order status has been checked.</p>
{search_form("/order", "id", "Order number", "1", "Check")}
</div>""", kind="vulnerable", lesson={
        "bug": "Blind SQL injection: the query is built from your text, but the page always says the same "
               "thing and hides all errors. The only clue is how long the page takes.",
        "try": "1 AND SLEEP(3)",
        "try_note": " - the page takes about 3 seconds longer to load. That delay proves the database ran your text.",
        "fix": "A parameterized query. Hiding errors alone does not fix SQL injection.",
    })


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
    entries = "".join(f'<li class="entry"><b>{name}</b>: {message}</li>' for name, message in GUESTBOOK)
    if not entries:
        entries = '<li class="entry">No messages yet. Be the first to sign!</li>'
    return page("Guestbook", f"""<div class="two-col">
<div class="card"><h2>Messages ({len(GUESTBOOK)})</h2><ul class="items">{entries}</ul></div>
<div class="card"><h2>Sign the guestbook</h2>
<form class="form" method="post">
  <label>Name <input type="text" name="name" value=""></label>
  <label>Message <textarea name="message"></textarea></label>
  <div class="form-row">
    <input type="submit" name="sign" value="Sign">
    <input type="submit" name="clear" value="Clear guestbook" class="button-ghost">
  </div>
</form></div>
</div>""", kind="vulnerable", lesson={
        "bug": "Messages are saved and shown to every later visitor without escaping. That is stored XSS: "
               "one attacker message attacks everyone who opens the page.",
        "try": "<i>hi from the guestbook</i>",
        "try_note": " - your message appears in italics for every visitor.",
        "fix": "Escape saved data every time it is written into a page.",
    })


# ---------------- Area behind a login ----------------
@lab.route("/account/login", methods=["GET", "POST"])
def account_login():
    error = ""
    if request.method == "POST":
        # Hidden CSRF token, like many real login forms have
        if request.form.get("csrf_token") != session.get("csrf_token"):
            error = '<div class="alert alert-bad">Invalid form token. Please try again.</div>'
        elif (request.form.get("user") == LAB_USERNAME
              and request.form.get("pass") == LAB_PASSWORD):
            session["user"] = LAB_USERNAME
            return redirect("/account/home")
        else:
            error = '<div class="alert alert-bad">Wrong username or password.</div>'
    session["csrf_token"] = str(time.time_ns())
    return page("Member login", f"""<div class="two-col">
<div class="card">
{error}
<form class="form" method="post">
  <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
  <label>Username <input type="text" name="user" value="" autocomplete="username"></label>
  <label>Password <input type="password" name="pass" value="" autocomplete="current-password"></label>
  <input type="submit" value="Log in">
</form>
</div>
<div class="card">
  <h2>Test account</h2>
  <p>This login exists to test the scanner's <strong>Login (optional)</strong> feature.</p>
  <div class="copy-row">Username: <code>{LAB_USERNAME}</code>
    <button type="button" class="button-ghost button-small" data-copy="{LAB_USERNAME}">Copy</button></div>
  <div class="copy-row">Password: <code>{LAB_PASSWORD}</code>
    <button type="button" class="button-ghost button-small" data-copy="{LAB_PASSWORD}">Copy</button></div>
  <p>Behind the login there is an XSS bug that the scanner can only find when you give it these details.</p>
</div>
</div>""", kind="info", lesson={
        "bug": "None here. The form has a hidden random token (like a CSRF token), so the scanner has to "
               "read the form first and send the token back, just like a browser.",
        "fix": "Nothing to fix. This page is here to test logging in.",
    })


@lab.route("/account/home")
def account_home():
    if session.get("user") != LAB_USERNAME:
        return redirect("/account/login")
    return page("Member area", """<div class="card">
<div class="alert alert-good">Welcome back! You are logged in as tester.</div>
<p><a class="button" href="/account/notes?title=todo">My notes</a></p>
<p><a href="/account/logout">Log out</a></p>
</div>""", kind="info")


@lab.route("/account/notes")
def account_notes():
    if session.get("user") != LAB_USERNAME:
        return redirect("/account/login")
    # BUG: reflected XSS that can only be found after logging in
    return page("Notes", f"""<div class="card">
<p class="result">Showing notes for: {request.args.get('title', '')}</p>
{search_form("/account/notes", "title", "Open another note", "todo", "Open")}
</div>""", kind="vulnerable", lesson={
        "bug": "Reflected XSS, but only reachable after logging in. A scanner that cannot log in never sees it.",
        "try": "<b>secret</b>",
        "fix": "Escape the title before showing it.",
    })


@lab.route("/account/logout")
def account_logout():
    session.clear()
    return redirect("/")


# ---------------- JavaScript app with a hidden API ----------------
@lab.route("/shop")
def shop():
    # The page itself has no links - only the JavaScript knows the API address
    return page("Shop", '<div class="card"><p class="result" id="app">Loading...</p></div>'
                        '<script src="/static/shop.js"></script>', kind="info", lesson={
        "bug": "No bug on this page itself. It has no links: the address of its search API is only written "
               "inside a JavaScript file, like in many modern web apps. That API has an SQL injection bug.",
        "fix": "The scanner reads JavaScript files as text to find such hidden API addresses.",
    })


@lab.route("/static/shop.js")
def shop_js():
    code = """
const API = "/api/items?search=";
fetch(API + "lamp").then(r => r.json()).then(items => {
  document.getElementById("app").textContent = "The shop API answered: " + items.length + " items found.";
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
    return page("Ping tool", f"""<div class="card">
<p class="result">Ping sent to {escape(host)}.</p>
{search_form("/ping", "host", "Address to ping", "127.0.0.1", "Ping")}
</div>""", kind="vulnerable", lesson={
        "bug": "A real version of this page would pass your text to a shell command like "
               "<code>ping -c 1 [your text]</code>. A <code>;</code> starts a second command. "
               "(The lab only pretends: it waits, but never runs anything.)",
        "try": "127.0.0.1;sleep 3",
        "try_note": " - the page takes about 3 seconds longer, as if the server ran sleep 3.",
        "fix": "Never pass user input to a shell. Check that it is a real IP address first.",
        "twin": ("/ping-safe?host=127.0.0.1", "Open the safe ping tool"),
    })


@lab.route("/ping-safe")
def ping_tool_safe():
    host = request.args.get("host", "")
    # SAFE: only accept a real IP address, never pass text to a shell
    try:
        ipaddress.ip_address(host)
        result = f"Ping sent to {escape(host)}."
    except ValueError:
        result = "Please enter a valid IP address."
    return page("Ping tool", f"""<div class="card">
<p class="result">{result}</p>
{search_form("/ping-safe", "host", "Address to ping", "127.0.0.1", "Ping")}
</div>""", kind="safe", lesson={
        "bug": "None. Anything that is not a real IP address is refused.",
        "try": "127.0.0.1;sleep 3",
        "try_note": " - you get \"Please enter a valid IP address\" straight away.",
        "fix": "This is the fixed version of the Ping tool.",
        "twin": ("/ping?host=127.0.0.1", "Open the vulnerable ping tool"),
    })


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

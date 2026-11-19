# WebVuln Scanner

A beginner-friendly web application vulnerability scanner written in Python and Flask.

You give it the URL of a website you are allowed to test. It crawls the site, finds the pages, forms and
URL parameters, and then checks them for common security problems: reflected XSS, SQL injection, open
redirects, missing security headers and exposed files. Everything is saved in a SQLite database, shown on a
dark web dashboard, and can be exported as an HTML or PDF report.

I built this project to learn how scanners like OWASP ZAP work on the inside. It is meant for learning
and for testing your own apps, not for replacing professional tools.

![Dashboard](docs/screenshots/dashboard.png)

---

## Features

| Module | What it does |
|---|---|
| **Target management** | Validates the URL (http/https only), only allows hosts on an allowlist, blocks private/internal IPs that are not allowlisted, always blocks cloud metadata IPs, and limits timeouts and requests |
| **Web crawler** | Finds pages by following links (same site only), reads forms and input fields, collects URL parameters, skips duplicates, stops at a max depth and max page count |
| **XSS detection** | Sends a harmless, random marker and checks if it turns into a real HTML tag or attribute. Escaped output is *not* reported |
| **SQL injection detection** | Error-based (looks for database error messages, then confirms) and boolean-based (compares "always true" and "always false" pages). Never sends destructive SQL |
| **Open redirect detection** | Tests redirect-like parameters with `https://example.com/...` and reads the `Location` header without following it |
| **Security header analyzer** | Checks CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy (missing **and** weak values) and version leaks in `Server` / `X-Powered-By` |
| **Directory discovery** | Checks about 30 common paths (`/.env`, `/.git/HEAD`, `/admin/`, `/backup/` ...), records every status code, detects "soft 404" pages and hides secrets in the evidence |
| **Findings + risk engine** | Every finding has name, URL, parameter, severity, confidence, description, evidence and fix. Severity comes from a fixed formula, not guesswork |
| **Database** | SQLite stores targets, scans (status, timestamps, settings), discovered URLs and findings |
| **Reports** | HTML report (view or download) and PDF report (ReportLab) |
| **Dashboard** | Totals, severity chart, recent scans, new scan form with live progress, results with filters, scan history |

---

## Tech stack (and why each one is used)

| Technology | Why |
|---|---|
| **Python 3.12** | Main language, easy to read |
| **Flask** | Small web framework for the dashboard and the JSON API. Easier to learn than Django |
| **Requests** | Sends the HTTP requests. Gives full control over redirects, timeouts and cookies |
| **BeautifulSoup** | Parses HTML to find links and forms, and to check if an XSS marker became a real tag |
| **SQLite** (built into Python) | Stores everything in one file, no database server needed |
| **ReportLab** | Builds the PDF report in pure Python |
| **Jinja2** (comes with Flask) | HTML templates with auto-escaping, so payloads in evidence can't run in the dashboard or report |
| **HTML / CSS / JavaScript** | The dashboard. Plain JS only, no frameworks |
| **pytest** | Automated tests |

---

## Architecture

```mermaid
flowchart TD
    User([User in browser]) -->|New Scan form| Routes[dashboard/routes.py<br/>Flask pages + JSON API]
    Routes -->|start scan| Engine[scanner/engine/scan_engine.py<br/>runs every step in a background thread]
    Engine --> TM[target_manager.py<br/>URL check, allowlist, private IP block]
    Engine --> Crawler[crawler/crawler.py<br/>pages, forms, parameters]
    Crawler --> UP[url_parser.py]
    Crawler --> FP[form_parser.py]
    Engine --> Mods{Vulnerability modules}
    Mods --> XSS[xss_scanner.py]
    Mods --> SQLI[sqli_scanner.py]
    Mods --> RED[redirect_scanner.py]
    Mods --> HDR[header_analyzer.py]
    Mods --> DIR[directory_scanner.py]
    Crawler & XSS & SQLI & RED & HDR & DIR -->|every HTTP request| RH[request_handler.py<br/>scope check, timeout, limit, delay]
    RH -->|HTTP| Target[(Target website)]
    XSS & SQLI & RED & HDR & DIR -->|Finding objects| FC[findings_collector.py]
    FC --> RA[risk_assessment.py<br/>severity formula]
    Engine -->|save results + progress| DB[(SQLite<br/>database/db.py)]
    Routes -->|read results| DB
    Routes --> Reports[reports/report_generator.py<br/>HTML + PDF]
```

**How the modules talk to each other, step by step:**

1. The **New Scan** page sends the form as JSON to `POST /api/scans` (`dashboard/routes.py`).
2. The route asks `target_manager.check_target()` if the URL is valid and allowed. If not, the user sees the reason.
3. A scan row is created in the database and `scan_engine.run_scan()` starts in a **background thread**, so
   the page doesn't freeze.
4. The engine creates one `RequestHandler`. **Every** module sends its requests through it, so the safety
   rules (same site only, timeout, request limit, delay, no automatic redirects) are enforced in one place.
5. The `Crawler` returns the pages and a list of **injection points** (each URL parameter or form, with its normal values).
6. Each vulnerability module tests those injection points and gives `Finding` objects to the `FindingsCollector`.
7. The collector removes duplicates and asks `risk_assessment` for the severity.
8. The engine saves everything to SQLite and updates the progress after each step. The browser checks
   `GET /api/scans/<id>` every second to move the progress bar.
9. The results page and the reports read the saved data back from the database.

### Folder structure

```
WebVuln Scanner/
├── app.py                      # starts the Flask app (python app.py)
├── config/settings.py          # allowlist, limits, database path
├── scanner/
│   ├── target_manager.py       # URL validation, allowlist, private IP blocking, scope check
│   ├── crawler/
│   │   ├── crawler.py          # breadth-first crawler, builds injection points
│   │   ├── url_parser.py       # normalize URLs, extract links, read parameters
│   │   └── form_parser.py      # find forms and their fields
│   ├── vulnerabilities/
│   │   ├── xss_scanner.py
│   │   ├── sqli_scanner.py
│   │   ├── redirect_scanner.py
│   │   ├── header_analyzer.py
│   │   └── directory_scanner.py
│   ├── engine/
│   │   ├── scan_engine.py      # runs all steps, saves progress and results
│   │   └── request_handler.py  # the only place that sends HTTP requests
│   └── analysis/
│       ├── findings_collector.py
│       └── risk_assessment.py
├── database/
│   ├── models.py               # table definitions (SQL)
│   └── db.py                   # all database reads and writes
├── reports/
│   ├── report_generator.py     # HTML + PDF
│   └── templates/report.html
├── dashboard/
│   ├── routes.py               # pages and API
│   └── templates/              # base, index, scan, results, history, error
├── static/css, static/js       # dark theme + progress/filter scripts
├── test_lab/vulnerable_app.py  # deliberately vulnerable site for testing (127.0.0.1 only)
├── tests/                      # pytest test suite
└── docs/screenshots/
```

**Changes from the first plan:** I added `test_lab/` (a local vulnerable site, so testing never needs the
internet or Docker), `tests/conftest.py` (starts the lab automatically during tests), and extra test files
for redirects, directories, risk, database and the dashboard.

---

## How the vulnerabilities are detected

**Reflected XSS.** For each parameter the scanner makes a random marker like `wvsk3j9qz` and sends
`wvsk3j9qz"'><wvsk3j9qzx>`. The made-up tag `<wvsk3j9qzx>` does nothing, even if it gets through. Then
BeautifulSoup parses the response:
- If the tag exists as a **real element**, the page lets us inject HTML: **High** confidence.
- If the payload is unencoded inside a `<script>` block: **Medium**.
- If it was escaped (`&lt;wvs...`) or not reflected at all: **no finding**. This is how simple reflection is
  told apart from injectable output, and it cuts out most false positives.

A second payload, `marker" markera="1`, checks if a quote can break out of an HTML attribute.

**SQL injection.**
- *Error-based:* add `'` to the value. If a database error appears (MySQL, PostgreSQL, SQLite, MSSQL and
  Oracle patterns) that wasn't on the normal page, confirm it: `''` (an escaped quote) should make the error
  go away, or for numbers `2-1` should give the same page as `1`. Confirmed = **High**, not confirmed = **Medium**.
- *Boolean-based:* compare the normal page with `1 AND 1=1` (always true) and `1 AND 1=2` (always false).
  True looks normal and false looks different: **Medium**. The page is loaded twice first, so pages that
  change on their own are skipped.
- Only read-only test inputs are used. No `DROP`, `DELETE`, `UPDATE`, `INSERT` or stacked queries.

**Open redirect.** Only parameters with redirect-style names (`url`, `next`, `redirect`, `goto` ...) or
URL-looking values are tested, with `https://example.com/wvs-redirect-check` and `//example.com/...`. The
scanner never follows the redirect. It only reads the `Location` header (or a meta refresh tag).

**Security headers.** One normal response is read and each header is checked for being missing *or* weak:
for example CSP with `'unsafe-inline'`, an HSTS `max-age` under 180 days, or a `Referrer-Policy` of `unsafe-url`.

**Directory discovery.** First a random path that can't exist is requested, to learn what the site's
"not found" page looks like. Then about 30 common paths are checked. Sensitive files must have the right
content too (a real `.git/HEAD` starts with `ref:`), and secrets in the evidence are replaced with `****`.

### Risk assessment (how severity is decided)

```
score = impact (1-5) x exploitability (1-5) x confidence factor (High 1.0, Medium 0.8, Low 0.6)

score >= 20  Critical      score >= 12  High      score >= 6  Medium      score >= 3  Low      else  Informational
```

The impact and exploitability numbers for each bug type are listed in
`scanner/analysis/risk_assessment.py`. For example, SQL injection is 5 x 4 = 20 (Critical at High
confidence) and an open redirect is 3 x 3 = 9 (Medium). Lower confidence can only lower the severity.

---

## Installation

You need **Python 3.10+** and **Git**.

```powershell
git clone https://github.com/<your-username>/WebVuln-Scanner.git
cd WebVuln-Scanner
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux / macOS
pip install -r requirements.txt
```

## Usage

**1. Start the vulnerable test lab** (optional, but great for a demo). In a terminal:

```powershell
python -m test_lab.vulnerable_app
```

It runs at http://127.0.0.1:5001 and listens **only on your own computer**.

**2. Start the scanner dashboard** in a second terminal:

```powershell
python app.py
```

Open http://127.0.0.1:5000, go to **New Scan**, enter `http://127.0.0.1:5001/`, tick the authorization
box and press **Start scan**. When the scan finishes you are taken to the results, where you can open
the HTML report or download the PDF.

> **Tip (Windows):** type `127.0.0.1` instead of `localhost`. Windows tries IPv6 (`::1`) first for
> `localhost`, and the lab only listens on IPv4, so each request waits for the IPv6 attempt to fail and
> the scan becomes very slow.

**Scanning other targets you own.** Only hosts on the allowlist can be scanned. By default that is
`localhost` and `127.0.0.1`. To add one, set an environment variable before starting the app:

```powershell
$env:WEBVULN_ALLOWED_HOSTS = "localhost,127.0.0.1,myapp.test"
python app.py
```

If an allowlisted name points to a private IP (like `10.0.0.5`), you must allowlist that IP too. Cloud
metadata addresses (`169.254.169.254`) are always blocked.

**Testing with OWASP Juice Shop or DVWA.** If you have Docker:

```powershell
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
docker run --rm -p 127.0.0.1:8080:80 vulnerables/web-dvwa
```

Then scan `http://127.0.0.1:3000/` or `http://127.0.0.1:8080/`. Note: Juice Shop is a JavaScript
single-page app, so this crawler (which doesn't run JavaScript) only sees a few pages. DVWA needs a
login, which this scanner doesn't support yet (see Limitations).

---

## Screenshots

| New Scan | Scan Results |
|---|---|
| ![New scan](docs/screenshots/new-scan.png) | ![Results](docs/screenshots/scan-results.png) |

| Scan History | HTML Report |
|---|---|
| ![History](docs/screenshots/history.png) | ![HTML report](docs/screenshots/html-report.png) |

---

## Testing

```powershell
python -m pytest -v
```

The tests start the vulnerable lab on a random port automatically, so no internet, Docker or manual setup
is needed. They check:

- URL validation, allowlist, private IP and metadata IP blocking, scope check, request limit
- crawling: links, forms, parameters, no duplicates, max depth, max pages, no external links
- XSS, SQLi and open redirect: **detected** on the vulnerable pages and **not reported** on the safe twin pages
- security headers with fake responses (missing, weak, and secure cases)
- directory discovery, status codes and secret hiding
- risk scores and severity levels
- database storage, SQL-injection-safe queries, scan history
- the dashboard pages, API safety checks, a full scan through the API, and the HTML/PDF reports
  (including that payloads are escaped)

---

## Limitations

- **No JavaScript rendering.** Single-page apps (React, Angular, Juice Shop) are mostly invisible to the crawler.
- **No login support.** Pages behind a login form are not scanned.
- **Reflected XSS only.** Stored and DOM-based XSS are not detected.
- **No time-based blind SQL injection**, and boolean-based results can still be false positives on unusual pages.
- **Small path list** for directory discovery, on purpose. This is not a brute-forcer.
- **Forms are really submitted** during testing (for example the login and contact forms). On a real
  app this can create log entries, emails or database rows. Only scan test environments.
- One scan runs in a simple background thread. There's no job queue, and closing the app stops running
  scans (they are marked as failed on the next start).
- Automated results always need a human to confirm them.

## Future improvements

- Login/session support (cookie or form login before crawling)
- Stored XSS and time-based SQL injection checks
- A cancel button for running scans
- Export findings as JSON/CSV
- Optional headless browser crawling for JavaScript-heavy sites
- Compare two scans of the same target to see what was fixed

---

## Responsible use

**Only scan websites you own or have written permission to test.** Scanning other people's websites
without permission is illegal in many countries (for example under the Computer Fraud and Abuse Act in
the US, the Computer Misuse Act in the UK, and the IT Act 2000 in India). That's why the scanner has an
allowlist, an authorization checkbox, request limits and polite delays. The included test lab is
deliberately insecure and must never be put on the internet.

## License

MIT, see [LICENSE](LICENSE).

# Interview notes for WebVuln Scanner

My own notes for explaining this project. Read the linked file next to each answer at least once.

---

## 1. The 30-second pitch

> "WebVuln Scanner is a small web vulnerability scanner I built in Python and Flask. You give it a
> website you are allowed to test. It crawls the site, finds every place that takes input, and tests those
> places for XSS, SQL injection, command injection and open redirects. It also checks security headers and
> common exposed files. Results go into SQLite and show on a dashboard, with HTML, PDF, JSON and CSV
> reports. I tested it on my own vulnerable lab, on DVWA and on OWASP Juice Shop, and it has around 100
> automated tests that run on GitHub Actions."

## 2. How it works, in one breath

Dashboard form -> **target_manager** checks the URL is allowed -> **scan_engine** starts a background
thread -> optional **auth** login -> **crawler** finds pages, forms, parameters and JavaScript API
paths -> each **vulnerability module** tests those inputs -> **findings_collector** removes duplicates
-> **risk_assessment** sets the severity -> everything is saved in **SQLite** -> **report_generator**
makes the reports. Every HTTP request goes through **request_handler**, which enforces the safety
rules.

---

## 3. Questions I should be ready for

**Q: How do you know a reflection is really XSS and not just text?**
I send a random made-up tag like `<wvsab12cdx>`, then parse the response with BeautifulSoup. If the parser
sees it as a *real element*, the page let me inject HTML. If the site escaped it (`&lt;wvs...`), the
parser sees plain text and I report nothing. The tag itself does nothing, so the test is harmless.
-> `scanner/vulnerabilities/xss_scanner.py`

**Q: How do you avoid false positives in SQL injection?**
Three methods, from strongest to weakest evidence:
1. *Error-based:* a `'` causes a database error that wasn't on the normal page. Then I confirm it: `''`
   (an escaped quote) should make the error go away, or for numbers `2-1` should show the same page as `1`.
2. *Boolean-based:* the "always true" page looks normal and the "always false" page is different. I load
   the normal page twice first, and skip pages that change on their own.
3. *Time-based:* `SLEEP(3)` makes the page about 3 s slower, `SLEEP(0)` is fast, and a second slow try is
   slow again.
-> `scanner/vulnerabilities/sqli_scanner.py`, `timing.py`

**Q: Isn't sending attacks dangerous?**
The payloads are chosen to be harmless: made-up HTML tags, single quotes, `SLEEP`, and `sleep` in the
shell. There's no `DROP`, `DELETE`, stacked queries or real shell commands. On top of that:
- an allowlist of targets, and private IPs are blocked
- an authorization checkbox
- a request limit and delay
- excluded paths (`logout`, `reset`, `delete`)
- only one *safe* submit button is sent per form
- stored XSS (which saves data) is off by default

**Q: How is severity decided?**
`impact x exploitability x confidence`, giving a score out of 25. Critical is 20 or more, High 12, Medium
6, Low 3. The numbers for each bug type are in one table, so the result is always the same and anyone
can check it. Lower confidence can only lower the severity.
-> `scanner/analysis/risk_assessment.py`

**Q: How does it scan pages behind a login without storing passwords?**
It opens the login page, finds the form with a password field, keeps the hidden fields (CSRF token),
fills in the username and password, and checks that the login form is gone afterwards. The password goes
straight to the scan thread in memory and is never written to the database. A test checks it never
appears in the database, results page or report.
-> `scanner/engine/auth.py`, `build_secrets()` in `scan_engine.py`

**Q: How did you handle JavaScript apps like Juice Shop?**
The crawler reads `.js` files *as text* and uses a regular expression to pick out paths like
`/rest/products/search?q=`, including paths inside template strings. It doesn't run the JavaScript.
That was enough to find Juice Shop's search SQL injection. Running a real browser would find more, but
would add a heavy dependency.
-> `scanner/crawler/url_parser.py`

**Q: Why Flask and SQLite instead of Django and PostgreSQL?**
The app is small and runs on one computer. Flask is easy to read, and SQLite needs no server and comes
with Python. Every database query uses `?` placeholders, the same fix my SQLi findings recommend.

**Q: Why a background thread?**
A scan can take minutes. Running it in a thread means the web page answers right away, and the browser
asks `/api/scans/<id>` every second for progress. The Cancel button sets a flag that the request handler
checks before every request.

**Q: How do you stop your own dashboard from being attacked?**
- Jinja2 auto-escaping, so payloads in evidence are shown as text
- a strict Content-Security-Policy with no inline scripts
- `X-Frame-Options: DENY`
- the start-scan API only accepts JSON and checks the `Origin` header, so other sites can't start scans in my browser
- it listens only on `127.0.0.1`
- CSV exports escape cells starting with `=`, `+`, `-` or `@` (CSV injection)

**Q: What was the hardest bug?**
Two good stories:
1. *DVWA's guestbook.* My form parser sent every submit button, so it also "clicked" **Clear Guestbook**
   on every test. That wiped my stored XSS marker and hid a real bug. Now only one safe button is sent, like
   a browser does, and buttons named clear/delete/reset are never used.
2. *Number values in SQLi.* My confirm step (`''`) only works inside text. For `id=1''` the SQL is still
   broken, so I added the `2-1` check for numbers. A unit test caught this.

**Q: What would you improve next?**
- An optional headless browser (Playwright) for JavaScript-heavy apps and DOM XSS
- testing POST/JSON APIs
- comparing two scans to see what got fixed

**Q: Did you use AI?**
Answer honestly. For example: "Yes, I used Claude as a pair programmer to help build it. Then I went
through each module, ran it against DVWA and Juice Shop, debugged the problems, and I can explain how
every part works."

---

## 4. Five-minute live demo

1. Start the lab (`python -m test_lab.vulnerable_app`) and the dashboard (`python app.py`).
2. Try to scan `https://example.com` and show the allowlist blocking it.
3. Scan `http://127.0.0.1:5001/` with the login box filled in (`tester` / `lab-password`) and stored XSS ticked.
4. While it runs, explain the progress bar and the Cancel button.
5. Open a SQL injection finding and walk through the evidence and the confirm step.
6. Show that the safe twin pages (`/safe-search`, `/product-safe`, `/ping-safe`) were *not* reported.
7. Download the PDF, then run `python -m pytest -q` to show the tests passing.

## 5. Words to know

| Term | Meaning in one line |
|---|---|
| Reflected XSS | Input from the request is put straight back into the page without escaping |
| Stored XSS | Input is saved and shown to every later visitor |
| Blind SQLi | The page looks the same either way, so you need true/false or timing to prove it |
| Injection point | One parameter or form field that accepts input |
| Soft 404 | A site that answers "200 OK" even for pages that don't exist |
| CSRF token | A hidden random value in a form that proves the form came from the real site |
| Allowlist | A list of the only things that are allowed (safer than a blocklist) |

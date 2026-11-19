"""
SQL Injection Scanner.

SQL injection happens when a website builds a database query by gluing user
input into the SQL text, for example:
    "SELECT * FROM products WHERE id = " + user_input
An attacker can then change the query and read or modify the database.

We only use SAFE test inputs. We never send DROP, DELETE, UPDATE, INSERT or
stacked queries (; ...). Two methods are used:

1. Error-based
   Add a single quote ' to the value. A vulnerable query breaks and the page
   often shows a database error such as "unrecognized token" or
   "You have an error in your SQL syntax".
   To be more sure, we then send two quotes '' (an escaped quote). If the error
   goes away again, the quote really was changing the SQL -> High confidence.

2. Boolean-based (only tried when no error was found)
   Send a condition that is always TRUE ("1 AND 1=1") and one that is always
   FALSE ("1 AND 1=2"). If the TRUE page looks like the normal page but the
   FALSE page is clearly different, the condition was run by the database.
   -> Medium confidence, because pages can change for other reasons.

3. Time-based (only tried when the first two found nothing)
   Some pages show exactly the same thing whatever happens in the database
   ("blind" SQL injection). Then we ask the database to WAIT, for example
   "1 AND SLEEP(3)". If the page takes about 3 seconds longer, and the same
   payload with SLEEP(0) is fast again, the database ran our input.
   We repeat the slow request to make sure it was not just a slow network.
   Payloads exist for MySQL/MariaDB and PostgreSQL. SQL Server would need a
   stacked query (; WAITFOR ...), which we do not send on purpose.
"""

import difflib
import logging
import re

from config import settings
from scanner.analysis.findings_collector import Finding, short_snippet
from scanner.engine.request_handler import RequestLimitReached

logger = logging.getLogger(__name__)

# Error messages from popular databases (regular expressions)
DATABASE_ERRORS = {
    "MySQL": [r"You have an error in your SQL syntax", r"Warning: mysql_",
              r"MySqlException", r"check the manual that corresponds to your MySQL"],
    "PostgreSQL": [r"PG::SyntaxError", r"pg_query\(\)", r"unterminated quoted string",
                   r"syntax error at or near", r"PSQLException"],
    "SQLite": [r"sqlite3\.OperationalError", r"SQLITE_ERROR", r"unrecognized token",
               r"near \"[^\"]*\": syntax error", r"SQLiteException"],
    "Microsoft SQL Server": [r"Unclosed quotation mark after the character string",
                             r"Microsoft OLE DB Provider for SQL Server", r"SqlException",
                             r"Incorrect syntax near"],
    "Oracle": [r"ORA-\d{5}", r"quoted string not properly terminated"],
    "Generic SQL": [r"SQL syntax.*error", r"SQLSTATE\[", r"ODBC .*Driver"],
}

DESCRIPTION = (
    "User input in this parameter appears to change the database query that "
    "the website runs. An attacker could read data they should not see, log in "
    "without a password, or in some cases change or delete data."
)
REMEDIATION = (
    "Use parameterized queries (prepared statements) everywhere, e.g. "
    "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)). Never build "
    "SQL by joining strings. Hide database error messages from users and give "
    "the database account only the permissions it needs."
)


def find_database_error(text):
    """Return (database name, matched text) if the page contains an SQL error."""
    for database, patterns in DATABASE_ERRORS.items():
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return database, match.group(0)
    return None


def similarity(text_a, text_b):
    """How similar two pages are, from 0.0 (different) to 1.0 (identical)."""
    return difflib.SequenceMatcher(None, text_a[:5000], text_b[:5000]).ratio()


def scan_sqli(handler, injection_points, collector):
    for point in injection_points:
        for param in point.testable_params():
            try:
                check_parameter(handler, point, param, collector)
            except RequestLimitReached:
                raise
            except Exception as error:
                logger.warning("SQLi test failed for %s %s: %s", point.url, param, error)


def check_parameter(handler, point, param, collector):
    original_value = point.params.get(param, "") or "1"
    baseline = handler.send_payload(point, param, original_value)
    if baseline is None:
        return

    # If the normal page already shows an SQL error we cannot tell the difference
    if find_database_error(baseline.text):
        return

    if error_based_test(handler, point, param, original_value, baseline, collector):
        return
    if boolean_based_test(handler, point, param, original_value, baseline, collector):
        return
    time_based_test(handler, point, param, original_value, baseline, collector)


def error_based_test(handler, point, param, original_value, baseline, collector):
    for quote in ("'", '"'):
        broken = handler.send_payload(point, param, original_value + quote)
        if broken is None:
            continue
        error = find_database_error(broken.text)
        if not error:
            continue

        database, matched_text = error
        # Confirm (text values): an escaped (doubled) quote should NOT cause the error
        fixed = handler.send_payload(point, param, original_value + quote + quote)
        confirmed = fixed is not None and not find_database_error(fixed.text)
        how = f"doubled quote {quote + quote} removed the error"
        if not confirmed and original_value.isdigit():
            # Confirm (number values): "2-1" should show the same page as "1"
            # if the database is really calculating our input.
            confirmed = numeric_math_check(handler, point, param, original_value, baseline)
            how = f"{int(original_value) + 1}-1 returned the same page as {original_value}"
        confidence = "High" if confirmed else "Medium"

        evidence = (
            f"Request: {point.method} {point.url}  {param}={original_value + quote}\n"
            f"Database error ({database}): {matched_text}\n"
            f"Confirmation: {how if confirmed else 'not confirmed'}\n"
            f"Response snippet: {short_snippet(broken.text, matched_text)}"
        )
        collector.add(Finding(
            name="SQL Injection (error-based)",
            vuln_type="sql_injection",
            url=point.url, parameter=param, confidence=confidence,
            description=DESCRIPTION, evidence=evidence, remediation=REMEDIATION,
        ))
        return True
    return False


def numeric_math_check(handler, point, param, original_value, baseline):
    """Return True if value "N+1-1" gives the normal page but "N+1" does not."""
    next_value = str(int(original_value) + 1)
    math_page = handler.send_payload(point, param, f"{next_value}-1")
    next_page = handler.send_payload(point, param, next_value)
    if math_page is None or next_page is None:
        return False
    return (similarity(baseline.text, math_page.text) > 0.98
            and similarity(baseline.text, next_page.text) < 0.98)


def boolean_based_test(handler, point, param, original_value, baseline, collector):
    # Load the normal page a second time to check the page is stable
    baseline_again = handler.send_payload(point, param, original_value)
    if baseline_again is None or similarity(baseline.text, baseline_again.text) < 0.98:
        return False  # page changes on its own (ads, timestamps) -> test not reliable

    test_pairs = [
        (f"{original_value} AND 1=1", f"{original_value} AND 1=2"),          # number values
        (f"{original_value}' AND '1'='1", f"{original_value}' AND '1'='2"),  # text values
    ]
    for true_value, false_value in test_pairs:
        true_response = handler.send_payload(point, param, true_value)
        false_response = handler.send_payload(point, param, false_value)
        if true_response is None or false_response is None:
            continue

        true_vs_base = similarity(baseline.text, true_response.text)
        false_vs_base = similarity(baseline.text, false_response.text)
        if true_vs_base > 0.95 and false_vs_base < 0.90:
            evidence = (
                f"Request (always true):  {param}={true_value} -> page {true_vs_base:.0%} similar to normal page\n"
                f"Request (always false): {param}={false_value} -> page {false_vs_base:.0%} similar to normal page\n"
                f"Status codes: normal={baseline.status_code}, true={true_response.status_code}, "
                f"false={false_response.status_code}"
            )
            collector.add(Finding(
                name="SQL Injection (boolean-based)",
                vuln_type="sql_injection",
                url=point.url, parameter=param, confidence="Medium",
                description=DESCRIPTION, evidence=evidence, remediation=REMEDIATION,
            ))
            return True
    return False


# (database, payload) - {v} is the normal value, {d} the seconds to wait
TIME_PAYLOADS = [
    ("MySQL/MariaDB", "{v} AND SLEEP({d})"),
    ("MySQL/MariaDB", "{v}' AND SLEEP({d}) AND '1'='1"),
    ("PostgreSQL", "{v} AND 1=(SELECT 1 FROM PG_SLEEP({d}))"),
    ("PostgreSQL", "{v}' AND 1=(SELECT 1 FROM PG_SLEEP({d})) AND '1'='1"),
]


def seconds(response):
    """How long the server took to answer (requests measures this for us)."""
    return response.elapsed.total_seconds()


def time_based_test(handler, point, param, original_value, baseline, collector,
                    delay=None):
    delay = delay or settings.SQLI_TIME_DELAY
    if handler.timeout < delay * 2 + 2:
        return False  # the request would time out before we could measure the delay

    second_baseline = handler.send_payload(point, param, original_value)
    if second_baseline is None:
        return False
    normal_time = max(seconds(baseline), seconds(second_baseline))
    if normal_time > 5:
        return False  # the page is too slow to measure reliably

    def extra_time(payload_template, wait):
        response = handler.send_payload(point, param, payload_template.format(v=original_value, d=wait))
        return None if response is None else seconds(response) - normal_time

    for database, template in TIME_PAYLOADS:
        slow = extra_time(template, delay)
        if slow is None or slow < delay * 0.8:
            continue
        fast = extra_time(template, 0)              # same payload, no waiting
        if fast is None or fast > delay * 0.5:
            continue
        slow_again = extra_time(template, delay)    # repeat to rule out a slow network
        if slow_again is None or slow_again < delay * 0.8:
            continue

        evidence = (
            f"Normal response time: {normal_time:.2f}s\n"
            f"{param}={template.format(v=original_value, d=delay)} -> +{slow:.2f}s, "
            f"again -> +{slow_again:.2f}s\n"
            f"{param}={template.format(v=original_value, d=0)} -> +{fast:.2f}s\n"
            f"Payload style: {database}"
        )
        collector.add(Finding(
            name="SQL Injection (time-based blind)",
            vuln_type="sql_injection",
            url=point.url, parameter=param, confidence="High",
            description=DESCRIPTION, evidence=evidence, remediation=REMEDIATION,
        ))
        return True
    return False

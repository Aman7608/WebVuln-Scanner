"""
Risk Assessment Engine - decides the severity of each finding.

Severity is NOT picked by hand for each finding. It is calculated with the
same simple formula every time:

    score = impact x exploitability x confidence_factor

  impact          (1-5)  how bad it is if an attacker uses this bug
  exploitability  (1-5)  how easy it is for an attacker to use it
  confidence      High = 1.0, Medium = 0.8, Low = 0.6
                  (how sure the scanner is that the bug is real)

The score (0-25) is turned into a severity level:

    20 or more  -> Critical
    12 or more  -> High
     6 or more  -> Medium
     3 or more  -> Low
     below 3    -> Informational

The impact and exploitability numbers for each type of bug are written in
RISK_RATINGS below, so anyone can read and question them. They are loosely
based on the OWASP Risk Rating Methodology (likelihood x impact).
"""

SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Informational"]

CONFIDENCE_FACTORS = {"High": 1.0, "Medium": 0.8, "Low": 0.6}

# vulnerability type -> (impact, exploitability)
RISK_RATINGS = {
    "command_injection":    (5, 5),  # attacker can run any command on the server
    "sql_injection":        (5, 4),  # can read or change the whole database
    "stored_xss":           (5, 4),  # attacker JavaScript runs for EVERY visitor of a page
    "reflected_xss":        (4, 4),  # can run attacker JavaScript in a victim's browser
    "sensitive_file":       (5, 4),  # secrets such as passwords or source code exposed
    "open_redirect":        (3, 3),  # helps phishing by abusing a trusted domain
    "exposed_resource":     (3, 3),  # admin pages, backups, directory listings
    "missing_csp":          (3, 2),  # no extra protection layer against XSS
    "missing_xfo":          (3, 2),  # page can be framed (clickjacking)
    "no_https":             (3, 2),  # traffic can be read or changed on the network
    "missing_hsts":         (2, 2),  # first visit can be downgraded to HTTP
    "missing_xcto":         (2, 2),  # browser may guess (sniff) file types
    "weak_header":          (2, 2),  # header exists but is set unsafely
    "missing_referrer":     (2, 1),  # full URLs may leak to other sites
    "info_disclosure":      (2, 1),  # server software/version is visible
    "interesting_resource": (1, 1),  # e.g. robots.txt - good to know, not a bug
}


def calculate_score(vuln_type, confidence):
    impact, exploitability = RISK_RATINGS.get(vuln_type, (1, 1))
    factor = CONFIDENCE_FACTORS.get(confidence, 0.6)
    return round(impact * exploitability * factor, 1)


def score_to_severity(score):
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    if score >= 3:
        return "Low"
    return "Informational"


def assess(vuln_type, confidence):
    """Return (severity, score) for a vulnerability type and confidence."""
    score = calculate_score(vuln_type, confidence)
    return score_to_severity(score), score


def severity_rank(severity):
    """Critical = 0, High = 1 ... used to sort findings, worst first."""
    try:
        return SEVERITY_LEVELS.index(severity)
    except ValueError:
        return len(SEVERITY_LEVELS)

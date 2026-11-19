"""Tests for the risk assessment engine and findings collector."""

from scanner.analysis.findings_collector import Finding, FindingsCollector, short_snippet
from scanner.analysis.risk_assessment import assess, score_to_severity


def make_finding(vuln_type="reflected_xss", confidence="High", url="http://x/a", parameter="q"):
    return Finding("Test", vuln_type, url, parameter, confidence, "d", "e", "r")


def test_score_thresholds():
    assert score_to_severity(25) == "Critical"
    assert score_to_severity(20) == "Critical"
    assert score_to_severity(16) == "High"
    assert score_to_severity(9) == "Medium"
    assert score_to_severity(4) == "Low"
    assert score_to_severity(1) == "Informational"


def test_known_ratings():
    assert assess("sql_injection", "High")[0] == "Critical"
    assert assess("reflected_xss", "High")[0] == "High"
    assert assess("open_redirect", "High")[0] == "Medium"
    assert assess("missing_xcto", "High")[0] == "Low"
    assert assess("interesting_resource", "High")[0] == "Informational"


def test_lower_confidence_never_raises_severity():
    for vuln in ["sql_injection", "reflected_xss", "open_redirect", "missing_csp"]:
        assert assess(vuln, "High")[1] >= assess(vuln, "Medium")[1] >= assess(vuln, "Low")[1]


def test_collector_removes_duplicates_and_sorts():
    collector = FindingsCollector()
    assert collector.add(make_finding("missing_xcto", parameter=""))
    assert collector.add(make_finding("sql_injection"))
    assert not collector.add(make_finding("sql_injection"))   # duplicate
    ordered = collector.sorted_findings()
    assert [f.vuln_type for f in ordered] == ["sql_injection", "missing_xcto"]
    assert collector.severity_counts()["Critical"] == 1


def test_short_snippet():
    text = "a" * 500 + "MARKER" + "b" * 500
    snippet = short_snippet(text, "MARKER", size=10)
    assert "MARKER" in snippet and len(snippet) < 40

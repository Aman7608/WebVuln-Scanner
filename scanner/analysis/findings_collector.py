"""
Findings Collector - keeps the list of problems found during a scan.

Every scanner module creates Finding objects and gives them to the collector.
The collector:
  * asks the risk assessment engine for the severity
  * removes duplicates (same bug, same URL, same parameter)
  * sorts the findings so the worst ones come first
"""

import logging
from dataclasses import asdict, dataclass

from scanner.analysis import risk_assessment

logger = logging.getLogger(__name__)

# Evidence is cut to this many characters so the database and reports stay small
MAX_EVIDENCE_LENGTH = 1500


@dataclass
class Finding:
    name: str              # human readable name, e.g. "Reflected Cross-Site Scripting"
    vuln_type: str         # key used by the risk engine, e.g. "reflected_xss"
    url: str               # affected URL
    parameter: str         # affected parameter ("" when not about a parameter)
    confidence: str        # High / Medium / Low
    description: str       # what the problem is
    evidence: str          # what the scanner saw that proves it
    remediation: str       # how to fix it
    severity: str = ""     # filled in by the collector
    risk_score: float = 0.0

    def to_dict(self):
        return asdict(self)


def short_snippet(text, keyword, size=120):
    """Return the text around a keyword, useful as evidence."""
    position = text.find(keyword)
    if position == -1:
        return text[: size * 2]
    start = max(0, position - size)
    end = min(len(text), position + len(keyword) + size)
    return ("..." if start else "") + text[start:end] + ("..." if end < len(text) else "")


class FindingsCollector:
    def __init__(self):
        self.findings = []
        self._seen = set()

    def add(self, finding):
        key = (finding.vuln_type, finding.url, finding.parameter)
        if key in self._seen:
            return False
        self._seen.add(key)

        finding.severity, finding.risk_score = risk_assessment.assess(
            finding.vuln_type, finding.confidence)
        finding.evidence = (finding.evidence or "")[:MAX_EVIDENCE_LENGTH]
        self.findings.append(finding)
        logger.info("[%s] %s at %s %s", finding.severity, finding.name,
                    finding.url, finding.parameter)
        return True

    def sorted_findings(self):
        return sorted(self.findings,
                      key=lambda f: (risk_assessment.severity_rank(f.severity), -f.risk_score))

    def severity_counts(self):
        counts = {level: 0 for level in risk_assessment.SEVERITY_LEVELS}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

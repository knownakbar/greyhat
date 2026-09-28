"""
Deduplicate and prioritize findings from all checks into a single,
ordered list ready for reporting.
"""
from __future__ import annotations

from collections import Counter
from typing import List

from .vuln_rules import Finding, SEVERITY_ORDER


def triage(findings: List[Finding]) -> List[Finding]:
    seen = set()
    deduped: List[Finding] = []
    for f in findings:
        key = (f.target, f.title, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return sorted(deduped, key=lambda f: (f.sort_key(), f.target))


def severity_summary(findings: List[Finding]) -> Counter:
    return Counter(f.severity for f in findings)


def risk_score(findings: List[Finding]) -> int:
    """A crude, explainable weighting purely for prioritization —
    not a formal CVSS calculation."""
    weights = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
    return sum(weights.get(f.severity, 0) for f in findings)

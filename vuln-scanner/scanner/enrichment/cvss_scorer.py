from __future__ import annotations


def score_to_severity(score: float) -> str:
    """Convert a CVSS numeric score to a severity label."""
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"

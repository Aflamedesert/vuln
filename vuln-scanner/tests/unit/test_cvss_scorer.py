from __future__ import annotations

import pytest

from scanner.enrichment.cvss_scorer import score_to_severity


@pytest.mark.parametrize(
    "score,expected",
    [
        (0.0, "NONE"),
        (2.0, "LOW"),
        (5.5, "MEDIUM"),
        (8.0, "HIGH"),
        (9.5, "CRITICAL"),
    ],
)
def test_score_to_severity(score: float, expected: str) -> None:
    assert score_to_severity(score) == expected


def test_score_boundary_low_medium() -> None:
    assert score_to_severity(3.9) == "LOW"
    assert score_to_severity(4.0) == "MEDIUM"


def test_score_boundary_medium_high() -> None:
    assert score_to_severity(6.9) == "MEDIUM"
    assert score_to_severity(7.0) == "HIGH"


def test_score_boundary_high_critical() -> None:
    assert score_to_severity(8.9) == "HIGH"
    assert score_to_severity(9.0) == "CRITICAL"

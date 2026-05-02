from __future__ import annotations

import pytest

from scanner.enrichment.cpe_matcher import version_in_range


@pytest.mark.parametrize(
    "version,start_inc,start_exc,end_inc,end_exc,expected",
    [
        # 1. No bounds at all — any version is in range
        ("2.0", None, None, None, None, True),
        # 2. At start_inc boundary — inclusive, so in range
        ("2.0", "2.0", None, None, None, True),
        # 3. At start_exc boundary — exclusive, so NOT in range
        ("2.0", None, "2.0", None, None, False),
        # 4. At end_inc boundary — inclusive, so in range
        ("3.0", None, None, "3.0", None, True),
        # 5. At end_exc boundary — exclusive, so NOT in range
        ("3.0", None, None, None, "3.0", False),
    ],
)
def test_version_in_range(
    version: str,
    start_inc: str | None,
    start_exc: str | None,
    end_inc: str | None,
    end_exc: str | None,
    expected: bool,
) -> None:
    assert version_in_range(version, start_inc, start_exc, end_inc, end_exc) == expected


def test_version_below_start_inc() -> None:
    assert version_in_range("1.9", "2.0", None, None, None) is False


def test_version_above_end_inc() -> None:
    assert version_in_range("3.1", None, None, "3.0", None) is False


def test_version_invalid_returns_false() -> None:
    assert version_in_range("not-a-version", "1.0", None, "3.0", None) is False

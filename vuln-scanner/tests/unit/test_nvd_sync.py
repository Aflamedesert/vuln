from __future__ import annotations

from datetime import date
from unittest.mock import patch

import pytest

from scanner.enrichment.nvd_sync import (
    _date_windows,
    _parse_cpe_matches,
    _parse_cve,
)

# ── _parse_cve ────────────────────────────────────────────────────────────────


def test_parse_cve_no_id_returns_none() -> None:
    assert _parse_cve({}) is None


def test_parse_cve_v31_primary() -> None:
    cve: dict[str, object] = {
        "id": "CVE-2021-44228",
        "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 10.0,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseSeverity": "CRITICAL",
                    },
                }
            ]
        },
        "published": "2021-12-10T00:00:00.000",
        "lastModified": "2021-12-10T00:00:00.000",
    }
    result = _parse_cve(cve)
    assert result is not None
    assert result["cve_id"] == "CVE-2021-44228"
    assert result["cvss_score"] == 10.0
    assert result["severity"] == "CRITICAL"
    assert result["description"] == "Log4Shell RCE"


def test_parse_cve_v31_non_primary_fallback() -> None:
    cve: dict[str, object] = {
        "id": "CVE-2021-00001",
        "descriptions": [],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Secondary",
                    "cvssData": {
                        "baseScore": 8.0,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                        "baseSeverity": "HIGH",
                    },
                }
            ]
        },
        "published": "2021-01-01T00:00:00.000",
        "lastModified": "2021-01-01T00:00:00.000",
    }
    result = _parse_cve(cve)
    assert result is not None
    assert result["cvss_score"] == 8.0
    assert result["severity"] == "HIGH"


def test_parse_cve_v30_fallback() -> None:
    cve: dict[str, object] = {
        "id": "CVE-2020-12345",
        "descriptions": [{"lang": "en", "value": "Test vuln"}],
        "metrics": {
            "cvssMetricV30": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 7.5,
                        "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "baseSeverity": "HIGH",
                    },
                }
            ]
        },
        "published": "2020-01-01T00:00:00.000",
        "lastModified": "2020-01-01T00:00:00.000",
    }
    result = _parse_cve(cve)
    assert result is not None
    assert result["cvss_score"] == 7.5


def test_parse_cve_v2_fallback() -> None:
    cve: dict[str, object] = {
        "id": "CVE-2010-99999",
        "descriptions": [],
        "metrics": {
            "cvssMetricV2": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 5.0,
                        "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                    },
                    "baseSeverity": "MEDIUM",
                }
            ]
        },
        "published": "2010-01-01T00:00:00.000",
        "lastModified": "2010-01-01T00:00:00.000",
    }
    result = _parse_cve(cve)
    assert result is not None
    assert result["cvss_score"] == 5.0
    assert result["severity"] == "MEDIUM"


def test_parse_cve_no_metrics() -> None:
    cve: dict[str, object] = {
        "id": "CVE-2000-00001",
        "descriptions": [{"lang": "en", "value": "Old CVE"}],
        "metrics": {},
        "published": "2000-01-01T00:00:00.000",
        "lastModified": "2000-01-01T00:00:00.000",
    }
    result = _parse_cve(cve)
    assert result is not None
    assert result["cvss_score"] is None
    assert result["severity"] is None


# ── _parse_cpe_matches ────────────────────────────────────────────────────────


def test_parse_cpe_matches_basic() -> None:
    cve: dict[str, object] = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                                "versionEndExcluding": "2.17.0",
                            }
                        ]
                    }
                ]
            }
        ]
    }
    matches = _parse_cpe_matches(cve)
    assert len(matches) == 1
    assert matches[0]["cpe_uri"] == "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    assert matches[0]["version_end_exc"] == "2.17.0"


def test_parse_cpe_matches_not_vulnerable_skipped() -> None:
    cve: dict[str, object] = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*",
                            }
                        ]
                    }
                ]
            }
        ]
    }
    matches = _parse_cpe_matches(cve)
    assert len(matches) == 0


def test_parse_cpe_matches_nested_nodes() -> None:
    cve: dict[str, object] = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [],
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:example:product:1.0:*",
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        ]
    }
    matches = _parse_cpe_matches(cve)
    assert len(matches) == 1
    assert matches[0]["cpe_uri"] == "cpe:2.3:a:example:product:1.0:*"


def test_parse_cpe_matches_empty() -> None:
    assert _parse_cpe_matches({}) == []
    assert _parse_cpe_matches({"configurations": []}) == []


# ── _date_windows ─────────────────────────────────────────────────────────────


def test_date_windows_covers_full_year() -> None:
    windows = _date_windows(2021)
    assert windows[0][0] == date(2021, 1, 1)
    assert windows[-1][1] == date(2021, 12, 31)


def test_date_windows_no_gap() -> None:
    windows = _date_windows(2021)
    for i in range(len(windows) - 1):
        prev_end = windows[i][1]
        next_start = windows[i + 1][0]
        gap = (next_start - prev_end).days
        assert gap == 1, f"Gap between windows {i} and {i+1}: {gap} days"


def test_date_windows_max_90_days() -> None:
    from scanner.enrichment.nvd_sync import _MAX_WINDOW_DAYS

    windows = _date_windows(2021)
    for start, end in windows:
        assert (end - start).days < _MAX_WINDOW_DAYS


# ── sync_nvd (mocked HTTP) ────────────────────────────────────────────────────


def test_sync_nvd_inserts_cve(tmp_path: object) -> None:
    from scanner.enrichment.nvd_sync import sync_nvd

    db_path = str(tmp_path / "test_cve.db")  # type: ignore[operator]

    cve_obj: dict[str, object] = {
        "id": "CVE-2021-44228",
        "descriptions": [{"lang": "en", "value": "Log4Shell"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 10.0,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseSeverity": "CRITICAL",
                    },
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ],
        "published": "2021-12-10T00:00:00.000",
        "lastModified": "2021-12-10T00:00:00.000",
    }

    first_page: dict[str, object] = {
        "totalResults": 1,
        "vulnerabilities": [{"cve": cve_obj}],
    }
    empty_page: dict[str, object] = {"totalResults": 0, "vulnerabilities": []}

    call_count = [0]

    def mock_fetch(
        start: object, end: object, idx: object, session: object
    ) -> dict[str, object]:
        call_count[0] += 1
        return first_page if call_count[0] == 1 else empty_page

    with (
        patch("scanner.enrichment.nvd_sync._fetch_page", side_effect=mock_fetch),
        patch("scanner.enrichment.nvd_sync.time.sleep"),
    ):
        count = sync_nvd(db_path, [2021])

    assert count == 1


def test_sync_nvd_empty_year(tmp_path: object) -> None:
    from scanner.enrichment.nvd_sync import sync_nvd

    db_path = str(tmp_path / "empty.db")  # type: ignore[operator]
    empty_page: dict[str, object] = {"totalResults": 0, "vulnerabilities": []}

    with (
        patch("scanner.enrichment.nvd_sync._fetch_page", return_value=empty_page),
        patch("scanner.enrichment.nvd_sync.time.sleep"),
    ):
        count = sync_nvd(db_path, [2020])

    assert count == 0

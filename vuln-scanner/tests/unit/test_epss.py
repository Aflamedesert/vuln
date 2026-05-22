from __future__ import annotations

import gzip
import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from scanner.enrichment.db import _create_schema
from scanner.enrichment.epss import _upsert_epss_rows, fetch_epss, get_epss_score


# ── schema ─────────────────────────────────────────────────────────────────────

def test_schema_has_epss_scores_table(mem_db: sqlite3.Connection) -> None:
    tables = {
        row[0]
        for row in mem_db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "epss_scores" in tables


# ── get_epss_score ─────────────────────────────────────────────────────────────

def test_get_epss_score_missing_returns_none(mem_db: sqlite3.Connection) -> None:
    assert get_epss_score("CVE-9999-0001", mem_db) is None


def test_get_epss_score_returns_tuple(mem_db: sqlite3.Connection) -> None:
    mem_db.execute(
        "INSERT INTO epss_scores (cve_id, probability, percentile, score_date) VALUES (?, ?, ?, ?)",
        ("CVE-2021-44228", 0.97530, 0.99800, "2024-01-01"),
    )
    mem_db.commit()
    result = get_epss_score("CVE-2021-44228", mem_db)
    assert result is not None
    prob, pct = result
    assert prob == pytest.approx(0.97530)
    assert pct == pytest.approx(0.99800)


def test_get_epss_score_returns_most_recent(mem_db: sqlite3.Connection) -> None:
    mem_db.executemany(
        "INSERT INTO epss_scores (cve_id, probability, percentile, score_date) VALUES (?, ?, ?, ?)",
        [
            ("CVE-2021-1234", 0.10, 0.50, "2024-01-01"),
            ("CVE-2021-1234", 0.90, 0.95, "2024-06-01"),
        ],
    )
    mem_db.commit()
    result = get_epss_score("CVE-2021-1234", mem_db)
    assert result is not None
    assert result[0] == pytest.approx(0.90)


# ── _upsert_epss_rows ──────────────────────────────────────────────────────────

_SAMPLE_CSV = """\
#model_version:v2023.03.01,score_date:2024-01-01T00:00:00+0000
cve,epss,percentile
CVE-2021-44228,0.97530,0.99800
CVE-2022-22965,0.97410,0.99780
CVE-2020-1234,0.00050,0.15000
"""


def test_upsert_epss_rows_count(mem_db: sqlite3.Connection) -> None:
    count = _upsert_epss_rows(_SAMPLE_CSV, "2024-01-01", mem_db)
    assert count == 3


def test_upsert_epss_rows_values(mem_db: sqlite3.Connection) -> None:
    _upsert_epss_rows(_SAMPLE_CSV, "2024-01-01", mem_db)
    row = mem_db.execute(
        "SELECT probability, percentile FROM epss_scores WHERE cve_id = ?",
        ("CVE-2021-44228",),
    ).fetchone()
    assert row is not None
    assert row[0] == pytest.approx(0.97530)
    assert row[1] == pytest.approx(0.99800)


def test_upsert_epss_rows_skips_comment_line(mem_db: sqlite3.Connection) -> None:
    _upsert_epss_rows(_SAMPLE_CSV, "2024-01-01", mem_db)
    # comment + header should NOT be treated as CVE rows
    bad = mem_db.execute(
        "SELECT cve_id FROM epss_scores WHERE cve_id LIKE '#%'",
    ).fetchone()
    assert bad is None


def test_upsert_epss_rows_replace_on_same_date(mem_db: sqlite3.Connection) -> None:
    csv_v1 = "#header\ncve,epss,percentile\nCVE-2021-44228,0.10,0.50\n"
    csv_v2 = "#header\ncve,epss,percentile\nCVE-2021-44228,0.90,0.95\n"
    _upsert_epss_rows(csv_v1, "2024-01-01", mem_db)
    _upsert_epss_rows(csv_v2, "2024-01-01", mem_db)
    rows = mem_db.execute(
        "SELECT probability FROM epss_scores WHERE cve_id = 'CVE-2021-44228'",
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == pytest.approx(0.90)


# ── fetch_epss ─────────────────────────────────────────────────────────────────

def _make_gz_response(csv_text: str) -> MagicMock:
    compressed = gzip.compress(csv_text.encode("utf-8"))
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.headers = {"Content-Length": str(len(compressed))}
    resp.iter_content.return_value = [compressed]
    return resp


def test_fetch_epss_returns_count(tmp_path: object) -> None:
    db_path = str(tmp_path / "test.db")  # type: ignore[operator]
    resp = _make_gz_response(_SAMPLE_CSV)
    with patch("scanner.enrichment.epss.requests.get", return_value=resp):
        count = fetch_epss(db_path)
    assert count == 3


def test_fetch_epss_stores_in_db(tmp_path: object) -> None:
    db_path = str(tmp_path / "test.db")  # type: ignore[operator]
    resp = _make_gz_response(_SAMPLE_CSV)
    with patch("scanner.enrichment.epss.requests.get", return_value=resp):
        fetch_epss(db_path)

    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT probability FROM epss_scores WHERE cve_id = 'CVE-2022-22965'"
    ).fetchone()
    conn.close()
    assert row is not None
    assert row[0] == pytest.approx(0.97410)

from __future__ import annotations

import sqlite3

import pytest

from scanner.core.models import ServiceInfo
from scanner.enrichment.cve_lookup import enrich_service


def _make_service(banner: str | None, version_string: str | None = None) -> ServiceInfo:
    return ServiceInfo(
        port=80,
        protocol="tcp",
        state="open",
        banner=banner,
        service_guess=None,
        version_string=version_string,
    )


def test_enrich_no_banner(mem_db: sqlite3.Connection) -> None:
    svc = _make_service(banner=None)
    enriched = enrich_service(svc, mem_db)
    assert enriched.cves == []
    assert enriched.cpe_uri is None


def test_enrich_matching_banner(sample_cve: sqlite3.Connection) -> None:
    """Banner exactly matches the Apache Log4j CPE inserted by sample_cve fixture."""
    svc = _make_service(banner="Apache Log4j 2.14.1")
    enriched = enrich_service(svc, sample_cve)
    cve_ids = [c.cve_id for c in enriched.cves]
    assert "CVE-2021-44228" in cve_ids


def test_enrich_matching_banner_cvss(sample_cve: sqlite3.Connection) -> None:
    svc = _make_service(banner="Apache Log4j 2.14.1")
    enriched = enrich_service(svc, sample_cve)
    match = next(c for c in enriched.cves if c.cve_id == "CVE-2021-44228")
    assert match.cvss_score == pytest.approx(10.0)
    assert match.severity == "CRITICAL"


def test_enrich_unknown_service(sample_cve: sqlite3.Connection) -> None:
    svc = _make_service(banner="UnknownThing 99.0")
    enriched = enrich_service(svc, sample_cve)
    assert enriched.cves == []


def test_enrich_service_version_outside_range(mem_db: sqlite3.Connection) -> None:
    from scanner.enrichment.db import upsert_cpe_match, upsert_cve

    upsert_cve(mem_db, {
        "cve_id": "CVE-2020-77777",
        "description": "Test range CVE",
        "cvss_score": 7.5,
        "cvss_vector": None,
        "severity": "HIGH",
        "published": "2020-01-01",
        "modified": "2020-01-01",
    })
    upsert_cpe_match(mem_db, "CVE-2020-77777", {
        "cpe_uri": "cpe:2.3:a:nginx:nginx:3.0.0:*:*:*:*:*:*:*",
        "version_start_inc": None,
        "version_start_exc": None,
        "version_end_inc": None,
        "version_end_exc": "3.0.0",
    })
    mem_db.commit()

    svc = ServiceInfo(
        port=80,
        protocol="tcp",
        state="open",
        banner="nginx/3.0.0",
        service_guess="http",
        version_string="3.0.0",
    )
    enriched = enrich_service(svc, mem_db)
    # 3.0.0 is at the end_exc boundary, so it's excluded from the range
    assert enriched.cves == []


def test_enrich_populates_epss_when_present(sample_cve: sqlite3.Connection) -> None:
    sample_cve.execute(
        "INSERT INTO epss_scores (cve_id, probability, percentile, score_date) VALUES (?, ?, ?, ?)",
        ("CVE-2021-44228", 0.97530, 0.99800, "2024-01-01"),
    )
    sample_cve.commit()
    svc = _make_service(banner="Apache Log4j 2.14.1")
    enriched = enrich_service(svc, sample_cve)
    match = next(c for c in enriched.cves if c.cve_id == "CVE-2021-44228")
    assert match.epss_probability == pytest.approx(0.97530)
    assert match.epss_percentile == pytest.approx(0.99800)


def test_enrich_epss_none_when_absent(sample_cve: sqlite3.Connection) -> None:
    svc = _make_service(banner="Apache Log4j 2.14.1")
    enriched = enrich_service(svc, sample_cve)
    match = next(c for c in enriched.cves if c.cve_id == "CVE-2021-44228")
    assert match.epss_probability is None
    assert match.epss_percentile is None


def test_enrich_results_uses_real_db(tmp_path: object) -> None:
    from scanner.enrichment.db import _create_schema, upsert_cpe_match, upsert_cve
    from scanner.enrichment.cve_lookup import enrich_results
    from scanner.core.models import ScanResult

    db_path = str(tmp_path / "cve_test.db")  # type: ignore[operator]
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys=ON")
    _create_schema(conn)
    upsert_cve(conn, {
        "cve_id": "CVE-2021-44228",
        "description": "Log4Shell",
        "cvss_score": 10.0,
        "cvss_vector": None,
        "severity": "CRITICAL",
        "published": "2021-12-10",
        "modified": "2021-12-10",
    })
    upsert_cpe_match(conn, "CVE-2021-44228", {
        "cpe_uri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
        "version_start_inc": None,
        "version_start_exc": None,
        "version_end_inc": None,
        "version_end_exc": None,
    })
    conn.commit()
    conn.close()

    scan_result = ScanResult(
        host="127.0.0.1",
        os_guess=None,
        os_confidence=0.0,
        ttl=None,
        tcp_window=None,
        services=[],
    )
    results = enrich_results([scan_result], db_path)
    assert len(results) == 1
    assert results[0].scan_result == scan_result

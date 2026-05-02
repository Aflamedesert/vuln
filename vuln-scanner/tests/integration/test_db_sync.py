from __future__ import annotations

import sqlite3

from scanner.enrichment.db import _create_schema, upsert_cpe_match, upsert_cve

_SAMPLE_CVE: dict[str, object] = {
    "cve_id": "CVE-2021-44228",
    "description": "Apache Log4j2 RCE",
    "cvss_score": 10.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "severity": "CRITICAL",
    "published": "2021-12-10",
    "modified": "2021-12-10",
}

_SAMPLE_CPE: dict[str, object] = {
    "cpe_uri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
    "version_start_inc": None,
    "version_start_exc": None,
    "version_end_inc": None,
    "version_end_exc": None,
}


def test_create_tables_idempotent() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    _create_schema(conn)
    _create_schema(conn)  # must not raise
    conn.close()


def test_upsert_cve_idempotent() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    _create_schema(conn)

    upsert_cve(conn, _SAMPLE_CVE)
    upsert_cve(conn, _SAMPLE_CVE)
    conn.commit()

    count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    assert count == 1
    conn.close()


def test_upsert_cpe_match() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    _create_schema(conn)

    upsert_cve(conn, _SAMPLE_CVE)
    upsert_cpe_match(conn, "CVE-2021-44228", _SAMPLE_CPE)
    conn.commit()

    row = conn.execute(
        "SELECT cpe_uri FROM cpe_matches WHERE cpe_uri = ?",
        ("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",),
    ).fetchone()
    assert row is not None
    assert row[0] == "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    conn.close()

from __future__ import annotations

import pytest

from scanner.enrichment.cpe_matcher import PRODUCT_ALIASES, extract_components, normalize_banner


@pytest.mark.parametrize(
    "banner,expected_product_raw,expected_version_fragment",
    [
        # vendor product version → Pattern 1
        ("OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "openssh", "8.2"),
        # product/version → Pattern 2 not applicable after normalisation (/ → space),
        # but Pattern 3 still extracts correctly
        ("nginx/1.18.0", "nginx", "1.18.0"),
        # product version → Pattern 3
        ("vsftpd 3.0.3", "vsftpd", "3.0.3"),
    ],
)
def test_extract_components_product_and_version(
    banner: str, expected_product_raw: str, expected_version_fragment: str
) -> None:
    comps = extract_components(banner)
    assert comps["product"] == expected_product_raw
    assert comps["version"] is not None
    assert expected_version_fragment in comps["version"]


def test_extract_components_apache_alias() -> None:
    """Apache/2.4.51 → raw product 'apache', aliased to 'http_server'."""
    comps = extract_components("Apache/2.4.51 (Unix)")
    assert comps["product"] == "apache"
    assert comps["version"] == "2.4.51"
    aliased = PRODUCT_ALIASES.get(comps["product"] or "", comps["product"])
    assert aliased == "http_server"


def test_extract_components_unknown_no_crash() -> None:
    comps = extract_components("unknown garbage xyz")
    # Must not raise; product or version (or both) will be None
    assert comps["product"] is None or comps["version"] is None


def test_normalize_banner_lowercases_and_strips() -> None:
    assert normalize_banner("  OpenSSH_8.2  ") == "openssh 8.2"


def test_normalize_banner_replaces_punctuation() -> None:
    result = normalize_banner("nginx/1.18.0-ubuntu")
    assert "/" not in result
    assert "-" not in result
    assert "_" not in result


# ── match_banner ──────────────────────────────────────────────────────────────

import sqlite3

from scanner.enrichment.cpe_matcher import match_banner
from scanner.enrichment.db import _create_schema, upsert_cpe_match, upsert_cve


def _fresh_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    _create_schema(conn)
    return conn


def test_match_banner_no_product_or_version() -> None:
    conn = _fresh_db()
    cpe, conf, method = match_banner("xyzgarbage", conn)
    assert cpe is None
    assert conf == 0.0
    assert method == "none"
    conn.close()


def test_match_banner_exact_match() -> None:
    conn = _fresh_db()
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

    cpe, conf, method = match_banner("Apache Log4j 2.14.1", conn)
    assert cpe == "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    assert conf == pytest.approx(0.95)
    assert method == "exact"
    conn.close()


def test_match_banner_no_match_returns_none() -> None:
    conn = _fresh_db()
    cpe, conf, method = match_banner("nginx/1.18.0", conn)
    assert cpe is None
    assert conf == 0.0
    assert method == "none"
    conn.close()


def test_match_banner_prefix_match() -> None:
    conn = _fresh_db()
    upsert_cve(conn, {
        "cve_id": "CVE-2020-11111",
        "description": "test",
        "cvss_score": 5.0,
        "cvss_vector": None,
        "severity": "MEDIUM",
        "published": "2020-01-01",
        "modified": "2020-01-01",
    })
    upsert_cpe_match(conn, "CVE-2020-11111", {
        "cpe_uri": "cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*",
        "version_start_inc": None,
        "version_start_exc": None,
        "version_end_inc": None,
        "version_end_exc": None,
    })
    conn.commit()

    # "openssh 8.2" → vendor=openssh, product=openssh, version=8.2
    # exact: cpe:2.3:a:openssh:openssh:8.2:... → not found
    # alias: vendor_alias[openssh]=openbsd, product_alias[openssh]=openssh
    # alias_cpe: cpe:2.3:a:openbsd:openssh:8.2:... → found!
    cpe, conf, method = match_banner("openssh 8.2", conn)
    assert cpe is not None
    assert method in ("alias", "exact")
    conn.close()

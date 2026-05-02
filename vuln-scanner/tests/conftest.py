from __future__ import annotations

import logging
import sqlite3

import pytest

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.layers.inet import IP, TCP  # noqa: E402

from scanner.enrichment.db import _create_schema, upsert_cpe_match, upsert_cve  # noqa: E402


@pytest.fixture
def syn_ack_linux() -> IP:
    return IP(ttl=64) / TCP(flags="SA", window=65535)


@pytest.fixture
def syn_ack_windows() -> IP:
    return IP(ttl=128) / TCP(flags="SA", window=8192)


@pytest.fixture
def syn_ack_cisco() -> IP:
    return IP(ttl=255) / TCP(flags="SA", window=4128)


@pytest.fixture
def mem_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    _create_schema(conn)
    yield conn  # type: ignore[misc]
    conn.close()


@pytest.fixture
def sample_cve(mem_db: sqlite3.Connection) -> sqlite3.Connection:
    upsert_cve(
        mem_db,
        {
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 JNDI lookup RCE (Log4Shell)",
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "published": "2021-12-10",
            "modified": "2021-12-10",
        },
    )
    upsert_cpe_match(
        mem_db,
        "CVE-2021-44228",
        {
            "cpe_uri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
            "version_start_inc": None,
            "version_start_exc": None,
            "version_end_inc": None,
            "version_end_exc": None,
        },
    )
    mem_db.commit()
    yield mem_db  # type: ignore[misc]

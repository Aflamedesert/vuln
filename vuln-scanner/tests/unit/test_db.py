from __future__ import annotations

import sqlite3

import pytest

from scanner.enrichment.db import _create_schema, get_db, log_sync, upsert_cve


def test_get_db_creates_file_and_schema(tmp_path: object) -> None:
    db_dir = tmp_path / "scanner"  # type: ignore[operator]
    db_path = str(db_dir / "cve.db")

    conn = get_db(db_path)
    assert conn is not None

    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "cves" in tables
    assert "cpe_matches" in tables
    assert "sync_log" in tables
    conn.close()

    assert (db_dir / "cve.db").exists()


def test_get_db_idempotent(tmp_path: object) -> None:
    db_path = str(tmp_path / "cve.db")  # type: ignore[operator]
    conn1 = get_db(db_path)
    conn1.close()
    conn2 = get_db(db_path)
    conn2.close()


def test_log_sync_records_count(tmp_path: object) -> None:
    db_path = str(tmp_path / "cve.db")  # type: ignore[operator]
    conn = get_db(db_path)

    log_sync(conn, 42)

    row = conn.execute("SELECT record_count FROM sync_log").fetchone()
    assert row is not None
    assert row[0] == 42
    conn.close()


def test_log_sync_records_timestamp(tmp_path: object) -> None:
    db_path = str(tmp_path / "cve.db")  # type: ignore[operator]
    conn = get_db(db_path)

    log_sync(conn, 0)

    row = conn.execute("SELECT synced_at FROM sync_log").fetchone()
    assert row is not None
    assert row[0] != ""
    conn.close()

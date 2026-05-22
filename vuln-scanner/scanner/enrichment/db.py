from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime


def get_db(path: str) -> sqlite3.Connection:
    """Open (or create) the CVE SQLite database at *path*, expanding ~ and creating dirs."""
    expanded = os.path.expanduser(path)
    os.makedirs(os.path.dirname(expanded), exist_ok=True)
    conn = sqlite3.connect(expanded)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _create_schema(conn)
    return conn


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS cves (
            cve_id       TEXT PRIMARY KEY,
            description  TEXT,
            cvss_score   REAL,
            cvss_vector  TEXT,
            severity     TEXT,
            published    TEXT,
            modified     TEXT
        );

        CREATE TABLE IF NOT EXISTS cpe_matches (
            cve_id              TEXT REFERENCES cves(cve_id),
            cpe_uri             TEXT,
            version_start_inc   TEXT,
            version_start_exc   TEXT,
            version_end_inc     TEXT,
            version_end_exc     TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_cpe_uri ON cpe_matches(cpe_uri);

        CREATE TABLE IF NOT EXISTS sync_log (
            synced_at    TEXT,
            record_count INTEGER
        );

        CREATE TABLE IF NOT EXISTS epss_scores (
            cve_id      TEXT,
            probability REAL,
            percentile  REAL,
            score_date  TEXT,
            PRIMARY KEY (cve_id, score_date)
        );
        """
    )
    conn.commit()


def upsert_cve(conn: sqlite3.Connection, cve_data: dict[str, object]) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO cves
            (cve_id, description, cvss_score, cvss_vector, severity, published, modified)
        VALUES (:cve_id, :description, :cvss_score, :cvss_vector, :severity, :published, :modified)
        """,
        cve_data,
    )


def upsert_cpe_match(
    conn: sqlite3.Connection,
    cve_id: str,
    match_data: dict[str, object],
) -> None:
    conn.execute(
        """
        INSERT INTO cpe_matches
            (cve_id, cpe_uri, version_start_inc, version_start_exc,
             version_end_inc, version_end_exc)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            cve_id,
            match_data.get("cpe_uri"),
            match_data.get("version_start_inc"),
            match_data.get("version_start_exc"),
            match_data.get("version_end_inc"),
            match_data.get("version_end_exc"),
        ),
    )


def log_sync(conn: sqlite3.Connection, record_count: int) -> None:
    conn.execute(
        "INSERT INTO sync_log (synced_at, record_count) VALUES (?, ?)",
        (datetime.now(UTC).isoformat(), record_count),
    )
    conn.commit()

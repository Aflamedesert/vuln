from __future__ import annotations

import csv
import gzip
import sqlite3
from datetime import UTC, datetime

import requests  # type: ignore[import-untyped]
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from scanner.enrichment.db import get_db

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

_console = Console()


def fetch_epss(db_path: str) -> int:
    """Download the current EPSS scores CSV and upsert into the local database."""
    score_date = datetime.now(UTC).date().isoformat()

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=_console,
    ) as progress:
        task = progress.add_task("Downloading EPSS scores…", total=None)

        resp = requests.get(EPSS_URL, stream=True, timeout=60)
        resp.raise_for_status()

        total = resp.headers.get("Content-Length")
        if total is not None:
            progress.update(task, total=int(total))

        chunks: list[bytes] = []
        for chunk in resp.iter_content(chunk_size=65536):
            if chunk:
                chunks.append(chunk)
                progress.update(task, advance=len(chunk))

    raw = b"".join(chunks)
    decompressed = gzip.decompress(raw).decode("utf-8")

    conn = get_db(db_path)
    count = _upsert_epss_rows(decompressed, score_date, conn)
    conn.close()
    return count


def _upsert_epss_rows(text: str, score_date: str, conn: sqlite3.Connection) -> int:
    lines = text.splitlines()
    data_lines = [ln for ln in lines if not ln.startswith("#")]
    reader = csv.DictReader(data_lines)

    count = 0
    batch: list[tuple[str, float, float, str]] = []
    for row in reader:
        batch.append((row["cve"], float(row["epss"]), float(row["percentile"]), score_date))
        count += 1
        if len(batch) == 500:
            _flush(conn, batch)
            batch = []

    if batch:
        _flush(conn, batch)

    conn.commit()
    return count


def _flush(conn: sqlite3.Connection, batch: list[tuple[str, float, float, str]]) -> None:
    conn.executemany(
        """
        INSERT OR REPLACE INTO epss_scores (cve_id, probability, percentile, score_date)
        VALUES (?, ?, ?, ?)
        """,
        batch,
    )


def get_epss_score(cve_id: str, conn: sqlite3.Connection) -> tuple[float, float] | None:
    """Return (probability, percentile) for *cve_id*, or None if not in the DB."""
    row = conn.execute(
        """
        SELECT probability, percentile FROM epss_scores
        WHERE cve_id = ?
        ORDER BY score_date DESC
        LIMIT 1
        """,
        (cve_id,),
    ).fetchone()
    if row is None:
        return None
    return (float(row[0]), float(row[1]))

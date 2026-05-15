from __future__ import annotations

import json
import os
import sqlite3
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scanner.reporting.models import ScanReport


def _get_history_db(db_path: str) -> sqlite3.Connection:
    expanded = os.path.expanduser(db_path)
    os.makedirs(os.path.dirname(expanded), exist_ok=True)
    conn = sqlite3.connect(expanded)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            target    TEXT,
            scan_date TEXT,
            label     TEXT,
            json_blob TEXT
        )
        """
    )
    conn.commit()
    return conn


def save_scan(db_path: str, report: ScanReport, label: str | None = None) -> int:
    from scanner.reporting.json_report import report_to_json_str

    data_str = report_to_json_str(report)
    conn = _get_history_db(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO scan_history (target, scan_date, label, json_blob) VALUES (?, ?, ?, ?)",
            (report.target, report.scan_started.isoformat(), label, data_str),
        )
        conn.commit()
        row_id: int = cur.lastrowid  # type: ignore[assignment]
        return row_id
    finally:
        conn.close()


def load_scan_by_label(db_path: str, label: str) -> dict[str, Any]:
    conn = _get_history_db(db_path)
    try:
        row = conn.execute(
            "SELECT json_blob FROM scan_history WHERE label = ? ORDER BY id DESC LIMIT 1",
            (label,),
        ).fetchone()
        if row is None:
            raise KeyError(f"No scan found with label {label!r}")
        return json.loads(row[0])  # type: ignore[no-any-return]
    finally:
        conn.close()


def list_scans(db_path: str) -> list[dict[str, Any]]:
    conn = _get_history_db(db_path)
    try:
        rows = conn.execute(
            "SELECT id, target, scan_date, label FROM scan_history ORDER BY id"
        ).fetchall()
        return [
            {"id": r[0], "target": r[1], "scan_date": r[2], "label": r[3]} for r in rows
        ]
    finally:
        conn.close()

from __future__ import annotations

import time
from datetime import date, timedelta
from typing import Any

import requests  # type: ignore[import-untyped]
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn

from scanner.enrichment.db import get_db, log_sync, upsert_cpe_match, upsert_cve

# NVD 2.0 REST API — legacy 1.1 JSON feeds were retired in March 2023
_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE = 2000
_BATCH_SIZE = 500
_RATE_DELAY = 0.6  # seconds between requests to stay within NVD rate limits
# NVD 2.0 API enforces a maximum date window of 120 days per request
_MAX_WINDOW_DAYS = 90


def _parse_cve(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Extract normalised CVE fields from an NVD 2.0 CVE object."""
    cve_id: str | None = cve.get("id")
    if not cve_id:
        return None

    description: str | None = None
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value")
            break

    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None

    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        primary = next((e for e in entries if e.get("type") == "Primary"), None)
        entry = primary or (entries[0] if entries else None)
        if entry:
            data = entry.get("cvssData", {})
            cvss_score = data.get("baseScore")
            cvss_vector = data.get("vectorString")
            severity = data.get("baseSeverity")
            break

    if cvss_score is None:
        entries = metrics.get("cvssMetricV2", [])
        primary = next((e for e in entries if e.get("type") == "Primary"), None)
        entry = primary or (entries[0] if entries else None)
        if entry:
            data = entry.get("cvssData", {})
            cvss_score = data.get("baseScore")
            cvss_vector = data.get("vectorString")
            severity = entry.get("baseSeverity")

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
    }


def _parse_cpe_matches(cve: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten all vulnerable cpeMatch entries from the configurations list."""
    matches: list[dict[str, Any]] = []

    def _collect_node(node: dict[str, Any]) -> None:
        for m in node.get("cpeMatch", []):
            if not m.get("vulnerable", False):
                continue
            matches.append(
                {
                    "cpe_uri": m.get("criteria"),
                    "version_start_inc": m.get("versionStartIncluding"),
                    "version_start_exc": m.get("versionStartExcluding"),
                    "version_end_inc": m.get("versionEndIncluding"),
                    "version_end_exc": m.get("versionEndExcluding"),
                }
            )
        for child in node.get("nodes", []):
            _collect_node(child)

    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            _collect_node(node)

    return matches


def _date_windows(year: int) -> list[tuple[date, date]]:
    """Split *year* into windows of at most _MAX_WINDOW_DAYS days."""
    start = date(year, 1, 1)
    end_of_year = date(year, 12, 31)
    windows: list[tuple[date, date]] = []
    while start <= end_of_year:
        chunk_end = min(start + timedelta(days=_MAX_WINDOW_DAYS - 1), end_of_year)
        windows.append((start, chunk_end))
        start = chunk_end + timedelta(days=1)
    return windows


def _fetch_page(
    start_date: date,
    end_date: date,
    start_index: int,
    session: requests.Session,
) -> dict[str, Any]:
    """Fetch one page of CVEs for the given date window from the NVD 2.0 API."""
    params: dict[str, str | int] = {
        "pubStartDate": f"{start_date}T00:00:00.000+00:00",
        "pubEndDate": f"{end_date}T23:59:59.999+00:00",
        "resultsPerPage": _PAGE_SIZE,
        "startIndex": start_index,
    }
    for attempt in range(3):
        try:
            resp = session.get(_NVD_API_URL, params=params, timeout=60)
            if resp.status_code == 429:
                time.sleep(30)
                continue
            resp.raise_for_status()
            result: dict[str, Any] = resp.json()
            return result
        except requests.RequestException:
            if attempt == 2:
                raise
            time.sleep(5)
    return {}


def sync_nvd(db_path: str, years: list[int]) -> int:
    """Sync NVD CVE data for *years* into the local database; returns total record count."""
    conn = get_db(db_path)
    total_records = 0
    batch_count = 0

    session = requests.Session()
    session.headers["User-Agent"] = "vuln-scanner/0.1 (github.com/example/vuln-scanner)"

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
    ) as progress:
        for year in years:
            windows = _date_windows(year)
            year_task = progress.add_task(f"[cyan]{year}", total=None)

            for win_start, win_end in windows:
                first_page = _fetch_page(win_start, win_end, 0, session)
                total_in_window: int = first_page.get("totalResults", 0)
                progress.update(
                    year_task,
                    description=f"[cyan]{year} [{win_start}…{win_end}]",
                    total=(progress.tasks[year_task].completed or 0) + total_in_window,
                )

                pages: list[dict[str, Any]] = [first_page]
                start = _PAGE_SIZE
                while start < total_in_window:
                    time.sleep(_RATE_DELAY)
                    pages.append(_fetch_page(win_start, win_end, start, session))
                    start += _PAGE_SIZE

                for page in pages:
                    for vuln in page.get("vulnerabilities", []):
                        cve_obj = vuln.get("cve", {})
                        cve_data = _parse_cve(cve_obj)
                        if cve_data is None:
                            continue
                        upsert_cve(conn, cve_data)
                        for match in _parse_cpe_matches(cve_obj):
                            upsert_cpe_match(conn, str(cve_data["cve_id"]), match)
                        batch_count += 1
                        total_records += 1
                        progress.advance(year_task)
                        if batch_count % _BATCH_SIZE == 0:
                            conn.commit()

                time.sleep(_RATE_DELAY)

            conn.commit()

    log_sync(conn, total_records)
    conn.close()
    return total_records

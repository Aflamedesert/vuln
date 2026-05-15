from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from scanner.core.models import EnrichedScanResult


@dataclass
class ScanReport:
    target: str
    scan_started: datetime
    scan_finished: datetime
    scanner_version: str
    cve_db_synced: str
    host_count: int
    open_port_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    hosts: list[EnrichedScanResult]


def build_report(
    target: str,
    started: datetime,
    finished: datetime,
    hosts: list[EnrichedScanResult],
    cve_db_synced: str = "unknown",
    scanner_version: str = "0.1.0",
) -> ScanReport:
    open_port_count = sum(
        1 for h in hosts for es in h.services if es.service.state == "open"
    )
    all_cves = [c for h in hosts for es in h.services for c in es.cves]

    def _count(sev: str) -> int:
        return sum(1 for c in all_cves if (c.severity or "").upper() == sev)

    return ScanReport(
        target=target,
        scan_started=started,
        scan_finished=finished,
        scanner_version=scanner_version,
        cve_db_synced=cve_db_synced,
        host_count=len(hosts),
        open_port_count=open_port_count,
        critical_count=_count("CRITICAL"),
        high_count=_count("HIGH"),
        medium_count=_count("MEDIUM"),
        low_count=_count("LOW"),
        hosts=hosts,
    )

from __future__ import annotations

import sqlite3

from scanner.core.models import (
    CVEMatch,
    EnrichedScanResult,
    EnrichedService,
    ScanResult,
    ServiceInfo,
)
from scanner.enrichment.cpe_matcher import match_banner, version_in_range
from scanner.enrichment.db import get_db
from scanner.enrichment.epss import get_epss_score


def enrich_service(service: ServiceInfo, conn: sqlite3.Connection) -> EnrichedService:
    """Match a service banner against the CVE database and return enriched results."""
    if service.banner is None:
        return EnrichedService(
            service=service,
            cpe_uri=None,
            cpe_confidence=0.0,
            match_method="none",
            cves=[],
        )

    cpe_uri, confidence, method = match_banner(service.banner, conn)

    cves: list[CVEMatch] = []
    if cpe_uri:
        rows = conn.execute(
            """
            SELECT DISTINCT cve_id, version_start_inc, version_start_exc,
                            version_end_inc, version_end_exc
            FROM cpe_matches
            WHERE cpe_uri = ?
            """,
            (cpe_uri,),
        ).fetchall()

        version = service.version_string or ""
        for row in rows:
            cve_id, si, se, ei, ee = row
            if version and not version_in_range(version, si, se, ei, ee):
                continue
            cve_row = conn.execute(
                "SELECT cve_id, description, cvss_score, severity, published"
                " FROM cves WHERE cve_id = ?",
                (cve_id,),
            ).fetchone()
            if cve_row:
                epss = get_epss_score(cve_row[0], conn)
                cves.append(
                    CVEMatch(
                        cve_id=cve_row[0],
                        description=cve_row[1],
                        cvss_score=cve_row[2],
                        severity=cve_row[3],
                        published=cve_row[4],
                        epss_probability=epss[0] if epss else None,
                        epss_percentile=epss[1] if epss else None,
                    )
                )

        cves.sort(key=lambda c: c.cvss_score or 0.0, reverse=True)

    return EnrichedService(
        service=service,
        cpe_uri=cpe_uri,
        cpe_confidence=confidence,
        match_method=method,
        cves=cves,
    )


def enrich_results(results: list[ScanResult], db_path: str) -> list[EnrichedScanResult]:
    """Enrich a list of scan results with CVE data from the local database."""
    conn = get_db(db_path)
    enriched: list[EnrichedScanResult] = []

    for scan_result in results:
        enriched_services: list[EnrichedService] = []
        for svc in scan_result.services:
            enriched_services.append(enrich_service(svc, conn))
        enriched.append(
            EnrichedScanResult(scan_result=scan_result, services=enriched_services)
        )

    conn.close()
    return enriched

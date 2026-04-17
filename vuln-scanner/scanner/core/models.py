from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ServiceInfo:
    port: int
    protocol: str  # always "tcp"
    state: str  # "open" | "filtered" | "closed"
    banner: str | None
    service_guess: str | None  # "ssh", "http", "mysql", etc.
    version_string: str | None  # e.g. "OpenSSH_8.2p1"


@dataclass
class ScanResult:
    host: str
    os_guess: str | None
    os_confidence: float  # 0.0 to 1.0
    ttl: int | None
    tcp_window: int | None
    services: list[ServiceInfo] = field(default_factory=list)


# ── Phase 3: enrichment models ────────────────────────────────────────────────


@dataclass
class CVEMatch:
    cve_id: str
    description: str | None
    cvss_score: float | None
    severity: str | None
    published: str | None


@dataclass
class EnrichedService:
    service: ServiceInfo
    cpe_uri: str | None
    cpe_confidence: float
    match_method: str
    cves: list[CVEMatch] = field(default_factory=list)


@dataclass
class EnrichedScanResult:
    scan_result: ScanResult
    services: list[EnrichedService] = field(default_factory=list)

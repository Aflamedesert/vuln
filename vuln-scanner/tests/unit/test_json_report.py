from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime

from scanner.core.models import EnrichedScanResult, EnrichedService, ScanResult, ServiceInfo
from scanner.reporting.json_report import load_json, write_json
from scanner.reporting.models import build_report


def _make_report(host: str = "127.0.0.1") -> object:
    svc = ServiceInfo(
        port=80,
        protocol="tcp",
        state="open",
        banner=None,
        service_guess="http",
        version_string=None,
    )
    scan_result = ScanResult(
        host=host,
        os_guess=None,
        os_confidence=0.0,
        ttl=None,
        tcp_window=None,
        services=[svc],
    )
    enriched = EnrichedScanResult(
        scan_result=scan_result,
        services=[
            EnrichedService(
                service=svc,
                cpe_uri=None,
                cpe_confidence=0.0,
                match_method="none",
                cves=[],
            )
        ],
    )
    started = datetime(2024, 1, 1, tzinfo=UTC)
    finished = datetime(2024, 1, 1, 0, 1, 0, tzinfo=UTC)
    return build_report(host, started, finished, [enriched])


def test_meta_keys(tmp_path: object) -> None:
    path = str(tmp_path / "scan.json")  # type: ignore[operator]
    write_json(_make_report(), path)  # type: ignore[arg-type]
    data = load_json(path)
    assert "meta" in data
    assert "hosts" in data


def test_roundtrip(tmp_path: object) -> None:
    path = str(tmp_path / "scan.json")  # type: ignore[operator]
    report = _make_report()
    write_json(report, path)  # type: ignore[arg-type]
    data = load_json(path)
    assert data["meta"]["summary"]["host_count"] == 1
    # host has one open port but no CVEs
    assert data["meta"]["summary"]["open_port_count"] == 1
    assert data["meta"]["summary"]["critical_count"] == 0
    assert len(data["hosts"]) == 1

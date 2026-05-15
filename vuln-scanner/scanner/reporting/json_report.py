from __future__ import annotations

import dataclasses
import json
from typing import Any

from scanner.reporting.models import ScanReport


def _build_dict(report: ScanReport) -> dict[str, Any]:
    return {
        "meta": {
            "target": report.target,
            "scan_started": report.scan_started.isoformat(),
            "scan_finished": report.scan_finished.isoformat(),
            "scanner_version": report.scanner_version,
            "cve_db_synced": report.cve_db_synced,
            "summary": {
                "host_count": report.host_count,
                "open_port_count": report.open_port_count,
                "critical_count": report.critical_count,
                "high_count": report.high_count,
                "medium_count": report.medium_count,
                "low_count": report.low_count,
            },
        },
        "hosts": [dataclasses.asdict(h) for h in report.hosts],
    }


def write_json(report: ScanReport, path: str) -> None:
    data = _build_dict(report)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def report_to_json_str(report: ScanReport) -> str:
    return json.dumps(_build_dict(report), indent=2)


def load_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)  # type: ignore[no-any-return]

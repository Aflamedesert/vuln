from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.reporting.models import ScanReport

_TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates"


def _report_to_dict(report: ScanReport) -> dict[str, Any]:
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


def write_html(report: ScanReport | dict[str, Any], path: str) -> None:
    data: dict[str, Any] = _report_to_dict(report) if isinstance(report, ScanReport) else report
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")
    rendered = template.render(**data)
    with open(path, "w", encoding="utf-8") as f:
        f.write(rendered)

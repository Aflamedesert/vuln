from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    target: str
    ports: str = "1-1024"
    timeout: float = 2.0
    concurrency: int = 100
    output_json: str | None = None
    output_html: str | None = None
    output_pdf: str | None = None
    db_path: str = field(default="~/.vuln-scanner/cve.db")

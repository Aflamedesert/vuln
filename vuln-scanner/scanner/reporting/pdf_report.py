from __future__ import annotations

import os
import tempfile
from typing import Any

from scanner.reporting.models import ScanReport


def write_pdf(report: ScanReport | dict[str, Any], path: str) -> None:
    from weasyprint import HTML

    from scanner.reporting.html_report import write_html

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".html")
    os.close(tmp_fd)
    try:
        write_html(report, tmp_path)
        HTML(filename=tmp_path).write_pdf(
            path,
            stylesheets=[],
            presentational_hints=True,
        )
    finally:
        os.unlink(tmp_path)

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from scanner.core.models import EnrichedScanResult
from scanner.reporting.models import ScanReport

_SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "NONE": "dim",
}


def print_host_table(result: EnrichedScanResult, console: Console) -> None:
    host = result.scan_result.host
    table = Table(title=f"Port scan — {host}", show_lines=False)
    table.add_column("Port", style="bold", justify="right")
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("CVEs", justify="right")
    table.add_column("Top CVSS", justify="right")
    table.add_column("Severity")

    shown = [es for es in result.services if es.service.state != "closed"]
    if not shown:
        console.print("[dim]No open or filtered ports found.[/dim]")
        return

    for es in shown:
        svc = es.service
        cve_count = len(es.cves)
        top_cvss = ""
        top_sev = ""
        sev_style = ""
        if es.cves:
            top = es.cves[0]
            top_cvss = f"{top.cvss_score:.1f}" if top.cvss_score is not None else ""
            top_sev = top.severity or ""
            sev_style = _SEVERITY_STYLE.get(top_sev, "")
        table.add_row(
            str(svc.port),
            svc.service_guess or "",
            svc.version_string or "",
            str(cve_count) if cve_count else "",
            top_cvss,
            f"[{sev_style}]{top_sev}[/{sev_style}]" if sev_style and top_sev else top_sev,
        )

    console.print(table)


def print_summary_panel(report: ScanReport, console: Console) -> None:
    duration = (report.scan_finished - report.scan_started).total_seconds()
    lines = [
        f"Target: [bold cyan]{report.target}[/bold cyan]",
        (
            f"Duration: {duration:.1f}s   "
            f"Hosts: {report.host_count}   "
            f"Open ports: {report.open_port_count}"
        ),
    ]

    for enriched in report.hosts:
        sr = enriched.scan_result
        if sr.os_guess:
            os_line = f"OS: [bold]{sr.os_guess}[/bold]  ({sr.os_confidence:.0%} confidence)"
            if sr.ttl is not None:
                os_line += f"   TTL={sr.ttl}"
            if sr.tcp_window is not None:
                os_line += f"   Window={sr.tcp_window}"
            lines.append(os_line)
            break

    if report.critical_count or report.high_count or report.medium_count or report.low_count:
        lines.append(
            f"[bold red]CRITICAL: {report.critical_count}[/bold red]  "
            f"[red]HIGH: {report.high_count}[/red]  "
            f"[yellow]MEDIUM: {report.medium_count}[/yellow]  "
            f"[cyan]LOW: {report.low_count}[/cyan]"
        )

    console.print(Panel("\n".join(lines), title="Scan Summary", expand=False))


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
    )

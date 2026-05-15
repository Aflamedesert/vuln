from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.table import Table

_SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}


@dataclass
class PortDiff:
    host: str
    port: int
    change: str  # "new" | "closed"
    service: str | None


@dataclass
class CVEDiff:
    host: str
    port: int
    cve_id: str
    change: str  # "new" | "resolved"
    severity: str | None


@dataclass
class DiffReport:
    scan_a_date: str
    scan_b_date: str
    new_ports: list[PortDiff] = field(default_factory=list)
    closed_ports: list[PortDiff] = field(default_factory=list)
    new_cves: list[CVEDiff] = field(default_factory=list)
    resolved_cves: list[CVEDiff] = field(default_factory=list)
    new_critical: int = 0
    new_high: int = 0


def _extract_ports(scan: dict[str, Any]) -> dict[tuple[str, int], str | None]:
    ports: dict[tuple[str, int], str | None] = {}
    for host_data in scan.get("hosts", []):
        host: str = host_data.get("scan_result", {}).get("host", "")
        for svc in host_data.get("scan_result", {}).get("services", []):
            if svc.get("state") == "open":
                ports[(host, int(svc["port"]))] = svc.get("service_guess")
    return ports


def _extract_cves(scan: dict[str, Any]) -> dict[tuple[str, int, str], str | None]:
    cves: dict[tuple[str, int, str], str | None] = {}
    for host_data in scan.get("hosts", []):
        host: str = host_data.get("scan_result", {}).get("host", "")
        for es in host_data.get("services", []):
            port = int(es.get("service", {}).get("port", 0))
            for cve in es.get("cves", []):
                cve_id: str = cve.get("cve_id", "")
                cves[(host, port, cve_id)] = cve.get("severity")
    return cves


def diff_scans(scan_a: dict[str, Any], scan_b: dict[str, Any]) -> DiffReport:
    date_a: str = scan_a.get("meta", {}).get("scan_started", "unknown")
    date_b: str = scan_b.get("meta", {}).get("scan_started", "unknown")

    ports_a = _extract_ports(scan_a)
    ports_b = _extract_ports(scan_b)
    cves_a = _extract_cves(scan_a)
    cves_b = _extract_cves(scan_b)

    new_ports = [
        PortDiff(host=h, port=p, change="new", service=svc)
        for (h, p), svc in ports_b.items()
        if (h, p) not in ports_a
    ]
    closed_ports = [
        PortDiff(host=h, port=p, change="closed", service=svc)
        for (h, p), svc in ports_a.items()
        if (h, p) not in ports_b
    ]
    new_cves = [
        CVEDiff(host=h, port=p, cve_id=cid, change="new", severity=sev)
        for (h, p, cid), sev in cves_b.items()
        if (h, p, cid) not in cves_a
    ]
    resolved_cves = [
        CVEDiff(host=h, port=p, cve_id=cid, change="resolved", severity=sev)
        for (h, p, cid), sev in cves_a.items()
        if (h, p, cid) not in cves_b
    ]

    new_critical = sum(1 for c in new_cves if (c.severity or "").upper() == "CRITICAL")
    new_high = sum(1 for c in new_cves if (c.severity or "").upper() == "HIGH")

    return DiffReport(
        scan_a_date=date_a,
        scan_b_date=date_b,
        new_ports=new_ports,
        closed_ports=closed_ports,
        new_cves=new_cves,
        resolved_cves=resolved_cves,
        new_critical=new_critical,
        new_high=new_high,
    )


def print_diff_report(diff: DiffReport, console: Console) -> None:
    console.print(f"\n[bold]Diff:[/bold] {diff.scan_a_date} → {diff.scan_b_date}\n")

    if diff.new_ports or diff.closed_ports:
        table = Table(title="Port Changes", show_lines=False)
        table.add_column("Change")
        table.add_column("Host")
        table.add_column("Port", justify="right")
        table.add_column("Service")
        for pd in diff.new_ports:
            table.add_row("[green]new[/green]", pd.host, str(pd.port), pd.service or "")
        for pd in diff.closed_ports:
            table.add_row("[red]closed[/red]", pd.host, str(pd.port), pd.service or "")
        console.print(table)
    else:
        console.print("[dim]No port changes.[/dim]")

    if diff.new_cves or diff.resolved_cves:
        table = Table(title="CVE Changes", show_lines=False)
        table.add_column("Change")
        table.add_column("Host")
        table.add_column("Port", justify="right")
        table.add_column("CVE ID")
        table.add_column("Severity")
        for cd in diff.new_cves:
            sev_style = _SEVERITY_STYLE.get(cd.severity or "", "")
            table.add_row(
                "[green]new[/green]",
                cd.host,
                str(cd.port),
                cd.cve_id,
                f"[{sev_style}]{cd.severity or ''}[/{sev_style}]"
                if sev_style
                else (cd.severity or ""),
            )
        for cd in diff.resolved_cves:
            table.add_row(
                "[dim]resolved[/dim]", cd.host, str(cd.port), cd.cve_id, cd.severity or ""
            )
        console.print(table)
    else:
        console.print("[dim]No CVE changes.[/dim]")

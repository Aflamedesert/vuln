from __future__ import annotations

import asyncio
import os
from datetime import date
from typing import cast

import click
from rich.console import Console
from rich.panel import Panel
from rich.status import Status
from rich.table import Table

from scanner.config import ScanConfig
from scanner.core.banner_grabber import grab_banner
from scanner.core.models import EnrichedScanResult, ServiceInfo
from scanner.core.os_fingerprint import fingerprint_os
from scanner.core.port_scanner import expand_targets, parse_port_range, scan_host

console = Console()


@click.group()
def cli() -> None:
    """vuln-scanner — network vulnerability scanner."""


@cli.command()
@click.option("--target", "-t", required=True, help="Target host or CIDR range.")
@click.option("--ports", "-p", default="1-1024", show_default=True, help="Port range to scan.")
@click.option(
    "--timeout", default=2.0, show_default=True, type=float, help="Per-probe timeout (s)."
)
@click.option(
    "--concurrency", default=100, show_default=True, type=int, help="Max concurrent probes."
)
@click.option("--output-json", default=None, help="Write JSON results to this path.")
@click.option("--output-html", default=None, help="Write HTML report to this path.")
@click.option("--output-pdf", default=None, help="Write PDF report to this path.")
def scan(
    target: str,
    ports: str,
    timeout: float,
    concurrency: int,
    output_json: str | None,
    output_html: str | None,
    output_pdf: str | None,
) -> None:
    """Scan a target for open ports and known vulnerabilities."""
    config = ScanConfig(
        target=target,
        ports=ports,
        timeout=timeout,
        concurrency=concurrency,
        output_json=output_json,
        output_html=output_html,
        output_pdf=output_pdf,
    )

    port_list = parse_port_range(config.ports)
    hosts = expand_targets(config.target)

    db_path = os.path.expanduser(config.db_path)
    db_exists = os.path.exists(db_path)

    for host in hosts:
        console.rule(f"[bold cyan]Scanning {host}[/bold cyan]")

        result = asyncio.run(scan_host(host, port_list, config))

        # Banner-grab every open port
        open_ports = [svc.port for svc in result.services if svc.state == "open"]
        if open_ports:

            async def _grab_all() -> list[ServiceInfo]:
                return cast(
                    list[ServiceInfo],
                    await asyncio.gather(*[grab_banner(host, p, timeout) for p in open_ports]),
                )

            banners: list[ServiceInfo] = asyncio.run(_grab_all())
            banner_map = {svc.port: svc for svc in banners}
            for svc in result.services:
                if svc.state == "open" and svc.port in banner_map:
                    enriched = banner_map[svc.port]
                    svc.banner = enriched.banner
                    svc.service_guess = enriched.service_guess
                    svc.version_string = enriched.version_string

        # OS fingerprint
        os_guess, os_confidence = fingerprint_os(result.ttl, result.tcp_window)
        result.os_guess = os_guess
        result.os_confidence = os_confidence

        # CVE enrichment (only when DB exists)
        enriched_result: EnrichedScanResult | None = None
        if db_exists:
            from scanner.enrichment.cve_lookup import enrich_results

            enriched_results = enrich_results([result], config.db_path)
            enriched_result = enriched_results[0] if enriched_results else None

        # Build results table
        table = Table(title=f"Port scan — {host}", show_lines=False)
        table.add_column("Port", style="bold", justify="right")
        table.add_column("State")
        table.add_column("Service")
        table.add_column("Version")
        table.add_column("CVEs", justify="right")
        table.add_column("Top Severity")

        state_style = {"open": "green", "closed": "dim", "filtered": "yellow"}
        severity_style = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "NONE": "dim",
        }

        shown = [s for s in result.services if s.state != "closed"]
        if not shown:
            console.print("[dim]No open or filtered ports found.[/dim]")
        else:
            enriched_map = (
                {es.service.port: es for es in enriched_result.services}
                if enriched_result
                else {}
            )
            for svc in shown:
                style = state_style.get(svc.state, "")
                esvc = enriched_map.get(svc.port)
                cve_count = len(esvc.cves) if esvc else 0
                top_sev = ""
                if esvc and esvc.cves:
                    top_sev = esvc.cves[0].severity or ""
                sev_style = severity_style.get(top_sev, "")
                table.add_row(
                    str(svc.port),
                    f"[{style}]{svc.state}[/{style}]",
                    svc.service_guess or "",
                    svc.version_string or "",
                    str(cve_count) if cve_count else "",
                    f"[{sev_style}]{top_sev}[/{sev_style}]" if top_sev else "",
                )
            console.print(table)

        # Summary panel
        summary_lines: list[str] = []

        if os_guess:
            os_text = f"[bold]{os_guess}[/bold]  (confidence: {os_confidence:.0%})"
            if result.ttl is not None:
                os_text += f"   TTL={result.ttl}"
            if result.tcp_window is not None:
                os_text += f"   Window={result.tcp_window}"
        else:
            os_text = "[dim]Could not determine OS.[/dim]"
        summary_lines.append(os_text)

        if enriched_result:
            all_cves = [c for es in enriched_result.services for c in es.cves]
            critical = sum(1 for c in all_cves if (c.severity or "").upper() == "CRITICAL")
            high = sum(1 for c in all_cves if (c.severity or "").upper() == "HIGH")
            if all_cves:
                summary_lines.append(
                    f"CVEs found: [bold]{len(all_cves)}[/bold]  "
                    f"[bold red]CRITICAL: {critical}[/bold red]  "
                    f"[red]HIGH: {high}[/red]"
                )

        console.print(Panel("\n".join(summary_lines), title="Summary", expand=False))


@cli.command("sync-db")
@click.option(
    "--db-path", default="~/.vuln-scanner/cve.db", show_default=True, help="Path to CVE database."
)
@click.option(
    "--year", "years", multiple=True, type=int, help="NVD year feed(s) to sync (repeatable)."
)
def sync_db(db_path: str, years: tuple[int, ...]) -> None:
    """Download and cache NVD CVE data locally."""
    from scanner.enrichment.nvd_sync import sync_nvd

    year_list: list[int] = list(years) if years else _default_years()

    with Status(f"[cyan]Syncing NVD feeds for years: {year_list}…", console=console):
        pass  # progress bars rendered inside sync_nvd

    record_count = sync_nvd(db_path, year_list)
    console.print(
        f"[green]Sync complete.[/green] Stored [bold]{record_count:,}[/bold] CVE records."
    )


def _default_years() -> list[int]:
    today = date.today()
    return [today.year, today.year - 1]


@cli.command()
@click.argument("scan_a", type=click.Path(exists=False))
@click.argument("scan_b", type=click.Path(exists=False))
@click.option("--output-json", default=None, help="Write diff JSON to this path.")
@click.option("--output-html", default=None, help="Write diff HTML report to this path.")
def diff(
    scan_a: str,
    scan_b: str,
    output_json: str | None,
    output_html: str | None,
) -> None:
    """Compare two scan result files and report changes."""
    click.echo("[Phase 4] not yet implemented")


@cli.command()
@click.argument("scan_json", type=click.Path(exists=False))
@click.option("--output-html", default=None, help="Write HTML report to this path.")
@click.option("--output-pdf", default=None, help="Write PDF report to this path.")
def report(
    scan_json: str,
    output_html: str | None,
    output_pdf: str | None,
) -> None:
    """Generate a human-readable report from a saved scan JSON."""
    click.echo("[Phase 5] not yet implemented")

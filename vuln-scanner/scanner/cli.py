from __future__ import annotations

import asyncio
import os
from datetime import UTC, date, datetime
from typing import cast

import click
from rich.console import Console

from scanner.config import ScanConfig
from scanner.core.banner_grabber import grab_banner
from scanner.core.models import EnrichedScanResult, EnrichedService, ScanResult, ServiceInfo
from scanner.core.os_fingerprint import fingerprint_os
from scanner.core.port_scanner import expand_targets, parse_port_range, scan_host

console = Console()


def _make_enriched(result: ScanResult) -> EnrichedScanResult:
    return EnrichedScanResult(
        scan_result=result,
        services=[
            EnrichedService(
                service=svc,
                cpe_uri=None,
                cpe_confidence=0.0,
                match_method="none",
                cves=[],
            )
            for svc in result.services
        ],
    )


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
    from scanner.diff.history import save_scan
    from scanner.reporting.cli_report import print_host_table, print_summary_panel
    from scanner.reporting.models import build_report

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

    started = datetime.now(UTC)
    all_enriched: list[EnrichedScanResult] = []

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
                    enriched_banner = banner_map[svc.port]
                    svc.banner = enriched_banner.banner
                    svc.service_guess = enriched_banner.service_guess
                    svc.version_string = enriched_banner.version_string

        # OS fingerprint
        os_guess, os_confidence = fingerprint_os(result.ttl, result.tcp_window)
        result.os_guess = os_guess
        result.os_confidence = os_confidence

        # CVE enrichment (only when DB exists)
        if db_exists:
            from scanner.enrichment.cve_lookup import enrich_results

            enriched_results = enrich_results([result], config.db_path)
            enriched = enriched_results[0] if enriched_results else _make_enriched(result)
        else:
            enriched = _make_enriched(result)

        all_enriched.append(enriched)
        print_host_table(enriched, console)

    finished = datetime.now(UTC)
    report = build_report(config.target, started, finished, all_enriched)
    save_scan(config.db_path, report)
    print_summary_panel(report, console)

    if config.output_json:
        from scanner.reporting.json_report import write_json

        write_json(report, config.output_json)
        console.print(f"[green]JSON saved:[/green] {config.output_json}")

    if config.output_html:
        from scanner.reporting.html_report import write_html

        write_html(report, config.output_html)
        console.print(f"[green]HTML saved:[/green] {config.output_html}")

    if config.output_pdf:
        from scanner.reporting.pdf_report import write_pdf

        write_pdf(report, config.output_pdf)
        console.print(f"[green]PDF saved:[/green] {config.output_pdf}")


@cli.command("sync-db")
@click.option(
    "--db-path", default="~/.vuln-scanner/cve.db", show_default=True, help="Path to CVE database."
)
@click.option(
    "--year", "years", multiple=True, type=int, help="NVD year feed(s) to sync (repeatable)."
)
def sync_db(db_path: str, years: tuple[int, ...]) -> None:
    """Download and cache NVD CVE data locally."""
    from rich.status import Status

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
@click.argument("scan_a", default=None, required=False)
@click.argument("scan_b", default=None, required=False)
@click.option("--label-a", default=None, help="Load first scan from history by label.")
@click.option("--label-b", default=None, help="Load second scan from history by label.")
@click.option("--output-json", default=None, help="Write diff JSON to this path.")
@click.option("--output-html", default=None, help="Write diff HTML report to this path.")
@click.option("--db-path", default="~/.vuln-scanner/cve.db", show_default=True, hidden=True)
def diff(
    scan_a: str | None,
    scan_b: str | None,
    label_a: str | None,
    label_b: str | None,
    output_json: str | None,
    output_html: str | None,
    db_path: str,
) -> None:
    """Compare two scan result files and report changes."""
    from scanner.diff.engine import diff_scans, print_diff_report
    from scanner.diff.history import load_scan_by_label
    from scanner.reporting.json_report import load_json

    if label_a and label_b:
        data_a = load_scan_by_label(db_path, label_a)
        data_b = load_scan_by_label(db_path, label_b)
    elif scan_a and scan_b:
        data_a = load_json(scan_a)
        data_b = load_json(scan_b)
    else:
        console.print("[red]Provide two file paths or --label-a / --label-b.[/red]")
        raise SystemExit(1)

    diff_report = diff_scans(data_a, data_b)
    print_diff_report(diff_report, console)

    if output_json:
        import dataclasses
        import json as _json
        with open(output_json, "w", encoding="utf-8") as f:
            _json.dump(dataclasses.asdict(diff_report), f, indent=2)
        console.print(f"[green]Diff JSON saved:[/green] {output_json}")


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
    from scanner.reporting.json_report import load_json

    if not output_html and not output_pdf:
        console.print("[yellow]Specify --output-html and/or --output-pdf.[/yellow]")
        raise SystemExit(1)

    data = load_json(scan_json)

    if output_html:
        from scanner.reporting.html_report import write_html

        write_html(data, output_html)
        console.print(f"[green]HTML saved:[/green] {output_html}")

    if output_pdf:
        from scanner.reporting.pdf_report import write_pdf

        write_pdf(data, output_pdf)
        console.print(f"[green]PDF saved:[/green] {output_pdf}")

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from scanner.cli import _default_years, cli
from scanner.core.models import (
    CVEMatch,
    EnrichedScanResult,
    EnrichedService,
    ScanResult,
    ServiceInfo,
)


def _svc(port: int = 80, state: str = "open") -> ServiceInfo:
    return ServiceInfo(
        port=port,
        protocol="tcp",
        state=state,
        banner=None,
        service_guess=None,
        version_string=None,
    )


def _scan_result(services: list[ServiceInfo] | None = None, ttl: int | None = None) -> ScanResult:
    return ScanResult(
        host="127.0.0.1",
        os_guess=None,
        os_confidence=0.0,
        ttl=ttl,
        tcp_window=None if ttl is None else 8192,
        services=services or [],
    )


def test_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0


def test_diff_no_changes() -> None:
    minimal: dict[str, object] = {"meta": {"scan_started": "2024-01-01T00:00:00"}, "hosts": []}
    with patch("scanner.reporting.json_report.load_json", return_value=minimal):
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", "a.json", "b.json"])
    assert result.exit_code == 0
    assert "no port changes" in result.output.lower()


def test_report_no_flags_exits() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["report", "scan.json"])
    assert result.exit_code != 0


def test_report_with_html_flag() -> None:
    minimal: dict[str, object] = {"meta": {"scan_started": "2024-01-01T00:00:00"}, "hosts": []}
    with (
        patch("scanner.reporting.json_report.load_json", return_value=minimal),
        patch("scanner.reporting.html_report.write_html"),
    ):
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "scan.json", "--output-html", "/tmp/r.html"])
    assert result.exit_code == 0


def test_default_years_returns_two() -> None:
    years = _default_years()
    assert len(years) == 2
    assert years[0] > years[1]


def test_sync_db_calls_sync_nvd() -> None:
    with patch("scanner.enrichment.nvd_sync.sync_nvd", return_value=42) as mock_sync:
        runner = CliRunner()
        result = runner.invoke(cli, ["sync-db", "--db-path", "/tmp/test_sync.db"])
        assert result.exit_code == 0
        mock_sync.assert_called_once()


def test_sync_db_with_year_option() -> None:
    with patch("scanner.enrichment.nvd_sync.sync_nvd", return_value=0):
        runner = CliRunner()
        result = runner.invoke(cli, ["sync-db", "--db-path", "/tmp/t.db", "--year", "2020"])
        assert result.exit_code == 0


def test_scan_no_open_ports_no_os() -> None:
    scan_result = _scan_result()

    with (
        patch("scanner.cli.scan_host", new_callable=AsyncMock) as mock_scan,
        patch("scanner.cli.fingerprint_os", return_value=(None, 0.0)),
        patch("scanner.diff.history.save_scan", return_value=1),
    ):
        mock_scan.return_value = scan_result
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--target", "127.0.0.1", "--ports", "80"])

    assert result.exit_code == 0


def test_scan_open_ports_no_db_with_os() -> None:
    svc = _svc(port=9999, state="open")
    scan_result = _scan_result(services=[svc], ttl=128)
    banner_svc = ServiceInfo(
        port=9999,
        protocol="tcp",
        state="open",
        banner="SSH-2.0-OpenSSH_8.2",
        service_guess="ssh",
        version_string="OpenSSH_8.2",
    )

    with (
        patch("scanner.cli.scan_host", new_callable=AsyncMock) as mock_scan,
        patch("scanner.cli.grab_banner", new_callable=AsyncMock) as mock_grab,
        patch("scanner.cli.fingerprint_os", return_value=("Windows", 0.9)),
        patch("scanner.diff.history.save_scan", return_value=1),
    ):
        mock_scan.return_value = scan_result
        mock_grab.return_value = banner_svc
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--target", "127.0.0.1", "--ports", "9999"])

    assert result.exit_code == 0


def test_scan_with_db_and_cves() -> None:
    svc = _svc(port=80, state="open")
    scan_result = _scan_result(services=[svc], ttl=64)
    # Give the scan_result non-None tcp_window so OS summary shows window info
    scan_result.tcp_window = 65535

    cve_match = CVEMatch(
        cve_id="CVE-2021-44228",
        description="Log4Shell",
        cvss_score=10.0,
        severity="CRITICAL",
        published="2021-12-10",
    )
    enriched_svc = EnrichedService(
        service=svc,
        cpe_uri="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
        cpe_confidence=0.95,
        match_method="exact",
        cves=[cve_match],
    )
    enriched_result = EnrichedScanResult(scan_result=scan_result, services=[enriched_svc])

    banner_svc = ServiceInfo(
        port=80,
        protocol="tcp",
        state="open",
        banner="Apache/2.4.51",
        service_guess="http",
        version_string="2.4.51",
    )

    with (
        patch("scanner.cli.scan_host", new_callable=AsyncMock) as mock_scan,
        patch("scanner.cli.grab_banner", new_callable=AsyncMock) as mock_grab,
        patch("scanner.cli.fingerprint_os", return_value=("Linux", 0.9)),
        patch("os.path.exists", return_value=True),
        patch("scanner.enrichment.cve_lookup.enrich_results", return_value=[enriched_result]),
        patch("scanner.diff.history.save_scan", return_value=1),
    ):
        mock_scan.return_value = scan_result
        mock_grab.return_value = banner_svc
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--target", "127.0.0.1", "--ports", "80"])

    assert result.exit_code == 0


def test_scan_with_db_no_enriched_services() -> None:
    scan_result = _scan_result()
    empty_enriched = EnrichedScanResult(scan_result=scan_result, services=[])

    with (
        patch("scanner.cli.scan_host", new_callable=AsyncMock) as mock_scan,
        patch("scanner.cli.fingerprint_os", return_value=("Linux", 0.9)),
        patch("os.path.exists", return_value=True),
        patch("scanner.enrichment.cve_lookup.enrich_results", return_value=[empty_enriched]),
        patch("scanner.diff.history.save_scan", return_value=1),
    ):
        mock_scan.return_value = scan_result
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--target", "127.0.0.1", "--ports", "80"])

    assert result.exit_code == 0

from __future__ import annotations

from scanner.diff.engine import diff_scans


def _make_scan(
    host: str = "10.0.0.1",
    open_ports: list[tuple[int, str | None]] | None = None,
    cves: list[tuple[int, str, str | None]] | None = None,
) -> dict:  # type: ignore[type-arg]
    services = []
    for port, svc in (open_ports or []):
        services.append({"port": port, "state": "open", "service_guess": svc})

    enriched_services = []
    for port, cve_id, severity in (cves or []):
        enriched_services.append({
            "service": {"port": port, "state": "open"},
            "cves": [{"cve_id": cve_id, "severity": severity}],
        })

    return {
        "meta": {"scan_started": "2024-01-01T00:00:00"},
        "hosts": [{"scan_result": {"host": host, "services": services}, "services": enriched_services}],
    }


def test_no_changes() -> None:
    scan = _make_scan(open_ports=[(80, "http")], cves=[(80, "CVE-2021-1234", "HIGH")])
    result = diff_scans(scan, scan)
    assert result.new_ports == []
    assert result.closed_ports == []
    assert result.new_cves == []
    assert result.resolved_cves == []


def test_new_port() -> None:
    scan_a = _make_scan(open_ports=[(80, "http")])
    scan_b = _make_scan(open_ports=[(80, "http"), (8080, "http-alt")])
    result = diff_scans(scan_a, scan_b)
    assert len(result.new_ports) == 1
    assert result.new_ports[0].port == 8080
    assert result.closed_ports == []


def test_closed_port() -> None:
    scan_a = _make_scan(open_ports=[(80, "http"), (23, "telnet")])
    scan_b = _make_scan(open_ports=[(80, "http")])
    result = diff_scans(scan_a, scan_b)
    assert result.new_ports == []
    assert len(result.closed_ports) == 1
    assert result.closed_ports[0].port == 23


def test_new_cve() -> None:
    scan_a = _make_scan()
    scan_b = _make_scan(cves=[(80, "CVE-2021-1234", "HIGH")])
    result = diff_scans(scan_a, scan_b)
    assert len(result.new_cves) == 1
    assert result.new_cves[0].cve_id == "CVE-2021-1234"
    assert result.resolved_cves == []


def test_severity_counts() -> None:
    scan_a = _make_scan()
    scan_b = _make_scan(cves=[
        (80, "CVE-2021-0001", "CRITICAL"),
        (443, "CVE-2021-0002", "CRITICAL"),
        (22, "CVE-2021-0003", "HIGH"),
    ])
    result = diff_scans(scan_a, scan_b)
    assert result.new_critical == 2
    assert result.new_high == 1

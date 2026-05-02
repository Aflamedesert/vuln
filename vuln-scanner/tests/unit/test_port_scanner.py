from __future__ import annotations

from scanner.core.port_scanner import expand_targets, parse_port_range


def test_parse_port_range_single() -> None:
    assert parse_port_range("22") == [22]


def test_parse_port_range_range() -> None:
    assert parse_port_range("80-83") == [80, 81, 82, 83]


def test_parse_port_range_mixed() -> None:
    assert parse_port_range("22,80-82,443") == [22, 80, 81, 82, 443]


def test_parse_port_range_deduplicates() -> None:
    result = parse_port_range("80,80-82")
    assert result == sorted(set(result))
    assert 80 in result


def test_expand_targets_single() -> None:
    assert expand_targets("192.168.1.1") == ["192.168.1.1"]


def test_expand_targets_cidr() -> None:
    hosts = expand_targets("192.168.1.0/30")
    # /30 has 2 usable hosts: .1 and .2
    assert len(hosts) == 2
    assert "192.168.1.1" in hosts
    assert "192.168.1.2" in hosts


def test_tcp_connect_probe_closed_port() -> None:
    from scanner.core.port_scanner import _tcp_connect_probe

    state, ttl, window = _tcp_connect_probe("127.0.0.1", 59999, 0.5)
    assert state in ("closed", "filtered")
    assert ttl is None
    assert window is None

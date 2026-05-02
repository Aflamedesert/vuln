from __future__ import annotations

import asyncio
import socket
import threading
import time

import pytest

from scanner.core.banner_grabber import grab_banner

_HOST = "127.0.0.1"
_PORT = 19922


class EchoHandler:
    BANNER = b"OpenSSH_8.2p1 Ubuntu\r\n"

    def handle(self, conn: socket.socket) -> None:
        try:
            conn.sendall(self.BANNER)
        finally:
            conn.close()


@pytest.fixture(scope="module")
def echo_server() -> None:  # type: ignore[return]
    handler = EchoHandler()
    stop_event = threading.Event()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((_HOST, _PORT))
    srv.listen(16)
    srv.settimeout(0.5)

    def _serve() -> None:
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
                t = threading.Thread(target=handler.handle, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
        srv.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    time.sleep(0.05)
    yield  # type: ignore[misc]
    stop_event.set()
    thread.join(timeout=2.0)


def test_banner_grabber_live(echo_server: None) -> None:
    info = asyncio.run(grab_banner(_HOST, _PORT, timeout=3.0))
    assert info.banner is not None
    assert "OpenSSH" in info.banner


def test_service_guess_live(echo_server: None) -> None:
    info = asyncio.run(grab_banner(_HOST, _PORT, timeout=3.0))
    assert info.service_guess == "ssh"


def test_state_is_open(echo_server: None) -> None:
    info = asyncio.run(grab_banner(_HOST, _PORT, timeout=3.0))
    assert info.state == "open"


def test_tcp_connect_probe_open_port(echo_server: None) -> None:
    from scanner.core.port_scanner import _tcp_connect_probe

    state, ttl, window = _tcp_connect_probe(_HOST, _PORT, 2.0)
    assert state == "open"
    assert ttl is None
    assert window is None


def test_scan_host_finds_open_port(echo_server: None) -> None:
    from scanner.config import ScanConfig
    from scanner.core.port_scanner import scan_host

    config = ScanConfig(target=_HOST)
    result = asyncio.run(scan_host(_HOST, [_PORT], config))

    assert result.host == _HOST
    open_svcs = [s for s in result.services if s.state == "open"]
    assert any(s.port == _PORT for s in open_svcs)


def test_scan_targets_basic(echo_server: None) -> None:
    from scanner.config import ScanConfig
    from scanner.core.port_scanner import scan_targets

    config = ScanConfig(target=_HOST, ports=str(_PORT))
    results = asyncio.run(scan_targets([_HOST], config))

    assert len(results) == 1
    assert results[0].host == _HOST

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from scanner.config import ScanConfig
from scanner.core.models import ScanResult, ServiceInfo

# Scapy is imported lazily so the rest of the CLI works without CAP_NET_RAW.
try:
    import scapy.layers.inet as _inet  # type: ignore[import-untyped,unused-ignore]
    import scapy.sendrecv as _sr  # type: ignore[import-untyped,unused-ignore]

    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def parse_port_range(port_str: str) -> list[int]:
    """Parse "22,80,443,8000-8080" into a sorted, deduplicated list of ints."""
    ports: list[int] = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            lo_str, hi_str = part.split("-", 1)
            ports.extend(range(int(lo_str), int(hi_str) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def expand_targets(target: str) -> list[str]:
    """Expand a single IP, CIDR range, or hostname into a list of host strings."""
    try:
        network = ipaddress.ip_network(target, strict=False)
        return [str(h) for h in network.hosts()]
    except ValueError:
        pass
    # Treat as hostname — resolve to validate but keep the original string
    try:
        socket.getaddrinfo(target, None)
    except socket.gaierror:
        pass
    return [target]


# ──────────────────────────────────────────────────────────────────────────────
# SYN probe (blocking, runs in executor)
# ──────────────────────────────────────────────────────────────────────────────


def _tcp_connect_probe(host: str, port: int, timeout: float) -> tuple[str, int | None, int | None]:
    """TCP connect fallback when CAP_NET_RAW is unavailable (no TTL/window info)."""
    import socket as _socket

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        rc = sock.connect_ex((host, port))
        return ("open" if rc == 0 else "closed"), None, None
    except OSError:
        return "filtered", None, None
    finally:
        sock.close()


def _syn_probe(host: str, port: int, timeout: float) -> tuple[str, int | None, int | None]:
    """Send a SYN and return (state, ttl, tcp_window).  Requires CAP_NET_RAW.

    Falls back to a plain TCP connect when raw sockets are unavailable.
    """
    if not _SCAPY_AVAILABLE:
        return _tcp_connect_probe(host, port, timeout)

    IP = _inet.IP
    TCP = _inet.TCP
    sr1 = _sr.sr1

    try:
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)
    except PermissionError:
        return _tcp_connect_probe(host, port, timeout)

    if resp is None:
        return "filtered", None, None

    ttl: int | None = getattr(resp, "ttl", None)
    window: int | None = None

    if resp.haslayer(TCP):
        tcp_layer = resp.getlayer(TCP)
        if tcp_layer is not None:
            flags = int(tcp_layer.flags)
            window = int(tcp_layer.window)

            if flags & 0x12:  # SYN-ACK → open
                rst = IP(dst=host) / TCP(dport=port, sport=int(tcp_layer.dport), flags="R")
                sr1(rst, timeout=1, verbose=0)
                return "open", ttl, window
            if flags & 0x04:  # RST → closed
                return "closed", ttl, window

    return "filtered", ttl, window


# ──────────────────────────────────────────────────────────────────────────────
# Async wrappers
# ──────────────────────────────────────────────────────────────────────────────

_executor = ThreadPoolExecutor(max_workers=256)


async def _async_syn_probe(
    host: str,
    port: int,
    timeout: float,
    sem: asyncio.Semaphore,
) -> tuple[str, int | None, int | None]:
    async with sem:
        loop = asyncio.get_event_loop()
        fn: Callable[[], tuple[str, int | None, int | None]] = partial(
            _syn_probe, host, port, timeout
        )
        return await loop.run_in_executor(_executor, fn)


async def scan_host(host: str, ports: list[int], config: ScanConfig) -> ScanResult:
    """Scan *host* on each port and return a ScanResult (services without banners)."""
    sem = asyncio.Semaphore(config.concurrency)
    tasks = [_async_syn_probe(host, port, config.timeout, sem) for port in ports]
    results = await asyncio.gather(*tasks)

    services: list[ServiceInfo] = []
    ttl_sample: int | None = None
    window_sample: int | None = None

    for port, (state, ttl, window) in zip(ports, results):
        if ttl is not None and ttl_sample is None:
            ttl_sample = ttl
        if window is not None and window_sample is None:
            window_sample = window

        services.append(
            ServiceInfo(
                port=port,
                protocol="tcp",
                state=state,
                banner=None,
                service_guess=None,
                version_string=None,
            )
        )

    return ScanResult(
        host=host,
        os_guess=None,
        os_confidence=0.0,
        ttl=ttl_sample,
        tcp_window=window_sample,
        services=services,
    )


async def scan_targets(targets: list[str], config: ScanConfig) -> list[ScanResult]:
    """Scan all *targets* and return one ScanResult per host."""
    ports = parse_port_range(config.ports)
    tasks = [scan_host(host, ports, config) for host in targets]
    return list(await asyncio.gather(*tasks))

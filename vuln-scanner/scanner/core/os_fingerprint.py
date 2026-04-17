from __future__ import annotations

from typing import TypedDict


class _FingerprintEntry(TypedDict):
    ttl_min: int
    ttl_max: int
    window: int
    os: str
    conf: float


_FINGERPRINTS: list[_FingerprintEntry] = [
    {"ttl_min": 60, "ttl_max": 64, "window": 5840, "os": "Linux", "conf": 0.9},
    {"ttl_min": 60, "ttl_max": 64, "window": 65535, "os": "macOS / BSD", "conf": 0.85},
    {"ttl_min": 120, "ttl_max": 128, "window": 8192, "os": "Windows", "conf": 0.9},
    {"ttl_min": 120, "ttl_max": 128, "window": 65535, "os": "Windows", "conf": 0.75},
    {"ttl_min": 240, "ttl_max": 255, "window": 4128, "os": "Cisco IOS", "conf": 0.9},
    {"ttl_min": 240, "ttl_max": 255, "window": 65535, "os": "Solaris / AIX", "conf": 0.8},
]


def fingerprint_os(ttl: int | None, tcp_window: int | None) -> tuple[str | None, float]:
    """Return (os_guess, confidence) based on TTL and TCP window size."""
    best_os: str | None = None
    best_conf: float = 0.0

    for fp in _FINGERPRINTS:
        ttl_match = ttl is not None and fp["ttl_min"] <= ttl <= fp["ttl_max"]
        win_match = tcp_window is not None and tcp_window == fp["window"]

        if ttl_match and win_match:
            if fp["conf"] > best_conf:
                best_os, best_conf = fp["os"], fp["conf"]
        elif ttl_match and tcp_window is None:
            if 0.6 > best_conf:
                best_os, best_conf = fp["os"], 0.6
        elif win_match and ttl is None:
            if 0.4 > best_conf:
                best_os, best_conf = fp["os"], 0.4

    # TTL-only match when window is present but unmatched
    if best_os is None and ttl is not None:
        for fp in _FINGERPRINTS:
            if fp["ttl_min"] <= ttl <= fp["ttl_max"]:
                best_os, best_conf = fp["os"], 0.6
                break

    return (best_os, best_conf)

from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

from scanner.core.os_fingerprint import fingerprint_os


@pytest.mark.parametrize(
    "ttl,window,expected_os",
    [
        (64, 5840, "Linux"),       # Linux: ttl 60-64, window 5840
        (128, 8192, "Windows"),    # Windows: ttl 120-128, window 8192
        (255, 4128, "Cisco IOS"),  # Cisco IOS: ttl 240-255, window 4128
        (55, 1000, None),          # no matching fingerprint
    ],
)
def test_fingerprint_os_guess(ttl: int, window: int, expected_os: str | None) -> None:
    os_guess, _ = fingerprint_os(ttl, window)
    assert os_guess == expected_os


def test_fingerprint_ttl_only_confidence() -> None:
    """When window is present but unmatched, TTL-only fallback returns confidence 0.6."""
    _, conf = fingerprint_os(64, 9999)
    assert conf == pytest.approx(0.6)


def test_fingerprint_windows_packet(syn_ack_windows: object) -> None:
    pkt = syn_ack_windows  # type: ignore[assignment]
    os_guess, conf = fingerprint_os(pkt.ttl, pkt[TCP].window)  # type: ignore[attr-defined]
    assert os_guess == "Windows"
    assert conf > 0.0


def test_fingerprint_cisco_packet(syn_ack_cisco: object) -> None:
    pkt = syn_ack_cisco  # type: ignore[assignment]
    os_guess, conf = fingerprint_os(pkt.ttl, pkt[TCP].window)  # type: ignore[attr-defined]
    assert os_guess == "Cisco IOS"
    assert conf > 0.0


def test_fingerprint_linux_packet_maps_to_macos_bsd(syn_ack_linux: object) -> None:
    """The syn_ack_linux fixture uses window=65535, which maps to the macOS/BSD entry."""
    pkt = syn_ack_linux  # type: ignore[assignment]
    os_guess, conf = fingerprint_os(pkt.ttl, pkt[TCP].window)  # type: ignore[attr-defined]
    assert os_guess == "macOS / BSD"
    assert conf > 0.0


def test_fingerprint_none_inputs() -> None:
    os_guess, conf = fingerprint_os(None, None)
    assert os_guess is None
    assert conf == 0.0


def test_fingerprint_ttl_only_window_is_none() -> None:
    """TTL matches but tcp_window is None → confidence 0.6 via the elif branch."""
    os_guess, conf = fingerprint_os(64, None)
    assert os_guess is not None
    assert conf == pytest.approx(0.6)


def test_fingerprint_window_only_ttl_is_none() -> None:
    """Window matches but ttl is None → confidence 0.4 via the elif branch."""
    os_guess, conf = fingerprint_os(None, 5840)
    assert os_guess is not None
    assert conf == pytest.approx(0.4)

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from scanner.core.models import ServiceInfo
from scanner.plugins.base import BasePlugin, PluginFinding, discover_plugins
from scanner.plugins.http_headers import HttpHeadersPlugin
from scanner.plugins.ssl_check import (
    SSLCheckPlugin,
    _check_cert_expiry,
    _classify_cert_error,
)


def _svc(
    port: int = 80,
    service_guess: str | None = "http",
    state: str = "open",
) -> ServiceInfo:
    return ServiceInfo(
        port=port,
        protocol="tcp",
        state=state,
        banner=None,
        service_guess=service_guess,
        version_string=None,
    )


# ── PluginFinding ──────────────────────────────────────────────────────────────

def test_plugin_finding_evidence_defaults_none() -> None:
    f = PluginFinding(plugin_name="p", title="t", description="d", severity="LOW")
    assert f.evidence is None


def test_plugin_finding_with_evidence() -> None:
    f = PluginFinding(plugin_name="p", title="t", description="d", severity="HIGH", evidence="42 days")
    assert f.evidence == "42 days"


# ── discover_plugins ───────────────────────────────────────────────────────────

def test_discover_plugins_returns_both_builtin_plugins() -> None:
    plugins = discover_plugins()
    names = {p.name for p in plugins}
    assert "http-headers" in names
    assert "ssl-check" in names


def test_discover_plugins_returns_base_plugin_instances() -> None:
    for plugin in discover_plugins():
        assert isinstance(plugin, BasePlugin)


# ── HttpHeadersPlugin ──────────────────────────────────────────────────────────

def test_http_applies_to_http_and_https() -> None:
    p = HttpHeadersPlugin()
    assert p.applies_to(_svc(80, "http"))
    assert p.applies_to(_svc(443, "https"))


def test_http_does_not_apply_to_other_services() -> None:
    p = HttpHeadersPlugin()
    assert not p.applies_to(_svc(22, "ssh"))
    assert not p.applies_to(_svc(3306, "mysql"))
    assert not p.applies_to(_svc(80, None))


def test_http_all_headers_present_no_findings() -> None:
    p = HttpHeadersPlugin()
    with patch("scanner.plugins.http_headers._fetch_headers") as m:
        m.return_value = {
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
        }
        assert p.run(_svc(80, "http"), "127.0.0.1") == []


def test_http_missing_x_frame_options() -> None:
    p = HttpHeadersPlugin()
    with patch("scanner.plugins.http_headers._fetch_headers") as m:
        m.return_value = {
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
        }
        findings = p.run(_svc(80, "http"), "127.0.0.1")
    assert len(findings) == 1
    assert "X-Frame-Options" in findings[0].title
    assert findings[0].severity == "MEDIUM"


def test_http_missing_csp() -> None:
    p = HttpHeadersPlugin()
    with patch("scanner.plugins.http_headers._fetch_headers") as m:
        m.return_value = {
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
        }
        findings = p.run(_svc(80, "http"), "127.0.0.1")
    assert any("Content-Security-Policy" in f.title for f in findings)


def test_http_missing_xcto() -> None:
    p = HttpHeadersPlugin()
    with patch("scanner.plugins.http_headers._fetch_headers") as m:
        m.return_value = {
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
        }
        findings = p.run(_svc(80, "http"), "127.0.0.1")
    assert any("X-Content-Type-Options" in f.title and f.severity == "LOW" for f in findings)


def test_https_missing_hsts_flagged_as_high() -> None:
    p = HttpHeadersPlugin()
    with patch("scanner.plugins.http_headers._fetch_headers") as m:
        m.return_value = {
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
        }
        findings = p.run(_svc(443, "https"), "127.0.0.1")
    assert any("Strict-Transport-Security" in f.title and f.severity == "HIGH" for f in findings)


def test_http_hsts_not_required_on_plain_http() -> None:
    p = HttpHeadersPlugin()
    with patch("scanner.plugins.http_headers._fetch_headers") as m:
        m.return_value = {
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
        }
        findings = p.run(_svc(80, "http"), "127.0.0.1")
    assert not any("Strict-Transport-Security" in f.title for f in findings)


def test_http_connection_error_returns_empty() -> None:
    p = HttpHeadersPlugin()
    with patch("scanner.plugins.http_headers._fetch_headers", return_value=None):
        assert p.run(_svc(80, "http"), "127.0.0.1") == []


# ── SSLCheckPlugin ─────────────────────────────────────────────────────────────

def test_ssl_applies_to_standard_ports() -> None:
    p = SSLCheckPlugin()
    assert p.applies_to(_svc(443, None))
    assert p.applies_to(_svc(8443, None))


def test_ssl_applies_to_https_service_guess() -> None:
    p = SSLCheckPlugin()
    assert p.applies_to(_svc(8080, "https"))


def test_ssl_does_not_apply_to_plain_http() -> None:
    p = SSLCheckPlugin()
    assert not p.applies_to(_svc(80, "http"))
    assert not p.applies_to(_svc(22, "ssh"))


def test_ssl_run_returns_empty_on_connection_error() -> None:
    p = SSLCheckPlugin()
    with patch("socket.create_connection", side_effect=OSError("refused")):
        assert p.run(_svc(443, "https"), "127.0.0.1") == []


# ── _check_cert_expiry ─────────────────────────────────────────────────────────

def test_cert_expiry_expired_is_critical() -> None:
    findings: list[PluginFinding] = []
    _check_cert_expiry({"notAfter": "Jan  1 00:00:00 2000 GMT"}, "ssl-check", findings)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].evidence is not None


def test_cert_expiry_within_30_days_is_high() -> None:
    future = datetime.now(timezone.utc) + timedelta(days=10)
    not_after = future.strftime("%b %d %H:%M:%S %Y GMT")
    findings: list[PluginFinding] = []
    _check_cert_expiry({"notAfter": not_after}, "ssl-check", findings)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "days remaining" in (findings[0].evidence or "")


def test_cert_expiry_far_future_no_findings() -> None:
    future = datetime.now(timezone.utc) + timedelta(days=365)
    not_after = future.strftime("%b %d %H:%M:%S %Y GMT")
    findings: list[PluginFinding] = []
    _check_cert_expiry({"notAfter": not_after}, "ssl-check", findings)
    assert findings == []


def test_cert_expiry_missing_key_no_findings() -> None:
    findings: list[PluginFinding] = []
    _check_cert_expiry({}, "ssl-check", findings)
    assert findings == []


def test_cert_expiry_bad_date_format_no_findings() -> None:
    findings: list[PluginFinding] = []
    _check_cert_expiry({"notAfter": "not-a-date"}, "ssl-check", findings)
    assert findings == []


# ── _classify_cert_error ───────────────────────────────────────────────────────

def test_classify_self_signed() -> None:
    findings: list[PluginFinding] = []
    _classify_cert_error("self signed certificate", "ssl-check", findings)
    assert len(findings) == 1
    assert findings[0].severity == "LOW"


def test_classify_self_signed_hyphenated() -> None:
    findings: list[PluginFinding] = []
    _classify_cert_error("self-signed certificate in chain", "ssl-check", findings)
    assert len(findings) == 1
    assert findings[0].severity == "LOW"


def test_classify_unable_to_get_local_issuer() -> None:
    findings: list[PluginFinding] = []
    _classify_cert_error("unable to get local issuer certificate", "ssl-check", findings)
    assert len(findings) == 1
    assert findings[0].severity == "LOW"


def test_classify_expired() -> None:
    findings: list[PluginFinding] = []
    _classify_cert_error("certificate has expired", "ssl-check", findings)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"


def test_classify_unknown_error_no_findings() -> None:
    findings: list[PluginFinding] = []
    _classify_cert_error("some other ssl error", "ssl-check", findings)
    assert findings == []


# ── named portfolio tests ──────────────────────────────────────────────────────

def test_discover_plugins() -> None:
    plugins = discover_plugins()
    names = {p.name for p in plugins}
    assert "http-headers" in names
    assert "ssl-check" in names
    assert len(plugins) >= 2


def test_http_plugin_applies_to() -> None:
    p = HttpHeadersPlugin()
    assert p.applies_to(_svc(80, "http"))
    assert p.applies_to(_svc(443, "https"))
    assert not p.applies_to(_svc(22, "ssh"))


def test_ssl_plugin_applies_to() -> None:
    p = SSLCheckPlugin()
    assert p.applies_to(_svc(443, None))
    assert not p.applies_to(_svc(22, "ssh"))


def test_plugin_finding_severity_valid() -> None:
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    for severity in valid_severities:
        f = PluginFinding(plugin_name="p", title="t", description="d", severity=severity)
        assert f.severity in valid_severities

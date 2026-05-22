from __future__ import annotations

import http.client
import ssl

from scanner.core.models import ServiceInfo
from scanner.plugins.base import BasePlugin, PluginFinding

_HEADER_CHECKS: list[tuple[str, str, str]] = [
    ("x-frame-options", "X-Frame-Options missing", "MEDIUM"),
    ("content-security-policy", "Content-Security-Policy missing", "MEDIUM"),
    ("x-content-type-options", "X-Content-Type-Options missing", "LOW"),
]


class HttpHeadersPlugin(BasePlugin):
    name = "http-headers"
    description = "Checks for missing HTTP security response headers."

    def applies_to(self, service: ServiceInfo) -> bool:
        return service.service_guess in ("http", "https")

    def run(self, service: ServiceInfo, host: str) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        is_https = service.service_guess == "https"
        headers = _fetch_headers(host, service.port, is_https)
        if headers is None:
            return findings

        for header_name, title, severity in _HEADER_CHECKS:
            if header_name not in headers:
                findings.append(
                    PluginFinding(
                        plugin_name=self.name,
                        title=title,
                        description=f"Response header '{header_name}' is absent.",
                        severity=severity,
                    )
                )

        if is_https and "strict-transport-security" not in headers:
            findings.append(
                PluginFinding(
                    plugin_name=self.name,
                    title="Strict-Transport-Security missing",
                    description="HSTS header absent on an HTTPS service.",
                    severity="HIGH",
                )
            )

        return findings


def _fetch_headers(
    host: str, port: int, is_https: bool, timeout: float = 5.0
) -> dict[str, str] | None:
    try:
        conn: http.client.HTTPConnection
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        result = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return result
    except OSError:
        return None

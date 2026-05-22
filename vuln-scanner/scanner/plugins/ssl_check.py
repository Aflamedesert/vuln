from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from scanner.core.models import ServiceInfo
from scanner.plugins.base import BasePlugin, PluginFinding

_WEAK_TLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})
_EXPIRY_WARN_DAYS = 30


class SSLCheckPlugin(BasePlugin):
    name = "ssl-check"
    description = "Checks TLS version, certificate expiry, and self-signed certificates."

    def applies_to(self, service: ServiceInfo) -> bool:
        return service.port in (443, 8443) or service.service_guess == "https"

    def run(self, service: ServiceInfo, host: str) -> list[PluginFinding]:
        findings: list[PluginFinding] = []

        # Connection 1: get TLS version without certificate verification
        ctx_none = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_none.check_hostname = False
        ctx_none.verify_mode = ssl.CERT_NONE

        tls_version: str | None = None
        try:
            with socket.create_connection((host, service.port), timeout=5.0) as raw:
                with ctx_none.wrap_socket(raw, server_hostname=host) as ssock:
                    tls_version = ssock.version()
        except OSError:
            return findings

        if tls_version in _WEAK_TLS:
            findings.append(
                PluginFinding(
                    plugin_name=self.name,
                    title=f"Weak TLS version: {tls_version}",
                    description="TLS versions below 1.2 are deprecated and insecure.",
                    severity="MEDIUM",
                    evidence=tls_version,
                )
            )

        # Connection 2: verify certificate to check expiry and detect self-signed
        ctx_verify = ssl.create_default_context()
        ctx_verify.check_hostname = False
        ctx_verify.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((host, service.port), timeout=5.0) as raw:
                with ctx_verify.wrap_socket(raw, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            if cert is not None:
                _check_cert_expiry(cert, self.name, findings)
        except ssl.SSLCertVerificationError as exc:
            _classify_cert_error(str(exc), self.name, findings)
        except OSError:
            pass

        return findings


def _check_cert_expiry(
    cert: dict[str, Any], plugin_name: str, findings: list[PluginFinding]
) -> None:
    not_after = cert.get("notAfter")
    if not isinstance(not_after, str):
        return
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except ValueError:
        return
    remaining = (expiry - datetime.now(UTC)).days
    if remaining < 0:
        findings.append(
            PluginFinding(
                plugin_name=plugin_name,
                title="Certificate expired",
                description="The TLS certificate has passed its expiry date.",
                severity="CRITICAL",
                evidence=f"Expired {abs(remaining)} days ago",
            )
        )
    elif remaining < _EXPIRY_WARN_DAYS:
        findings.append(
            PluginFinding(
                plugin_name=plugin_name,
                title="Certificate expiring soon",
                description=f"The TLS certificate expires within {_EXPIRY_WARN_DAYS} days.",
                severity="HIGH",
                evidence=f"{remaining} days remaining",
            )
        )


def _classify_cert_error(
    error_msg: str, plugin_name: str, findings: list[PluginFinding]
) -> None:
    err = error_msg.lower()
    if "certificate has expired" in err or ("expired" in err and "self" not in err):
        findings.append(
            PluginFinding(
                plugin_name=plugin_name,
                title="Certificate expired",
                description="The TLS certificate has passed its expiry date.",
                severity="CRITICAL",
            )
        )
    elif (
        "self signed" in err
        or "self-signed" in err
        or "unable to get local issuer" in err
    ):
        findings.append(
            PluginFinding(
                plugin_name=plugin_name,
                title="Self-signed certificate",
                description="The TLS certificate is not signed by a trusted CA.",
                severity="LOW",
            )
        )

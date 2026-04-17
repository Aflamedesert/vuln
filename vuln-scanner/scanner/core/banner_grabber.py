from __future__ import annotations

import asyncio
import re
import ssl

from scanner.core.models import ServiceInfo

# Maps port numbers to well-known service names
_SERVICE_NAMES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    80: "http",
    443: "https",
    3306: "mysql",
    8080: "http",
    8443: "https",
}


def _guess_service(port: int, banner: str | None) -> str | None:
    if port in _SERVICE_NAMES:
        return _SERVICE_NAMES[port]
    if banner:
        lower = banner.lower()
        if "ssh" in lower:
            return "ssh"
        if "ftp" in lower:
            return "ftp"
        if "smtp" in lower or "esmtp" in lower:
            return "smtp"
        if "http" in lower:
            return "http"
        if "mysql" in lower:
            return "mysql"
    return None


def _parse_version(port: int, banner: str) -> str | None:
    patterns: list[str] = []
    if port == 22:
        patterns = [r"SSH-[\d.]+-(\S+)"]
    elif port in (21, 25):
        patterns = [r"220[- ](\S.+)"]
    elif port in (80, 8080, 443, 8443):
        patterns = [r"[Ss]erver:\s*(.+)"]
    elif port == 3306:
        patterns = [r"([\d]+\.[\d]+\.[\d]+\S*)"]
    else:
        patterns = [r"([\w][\w./\-_]+ ?[\d.]+\S*)"]

    for pat in patterns:
        m = re.search(pat, banner)
        if m:
            return m.group(1).strip()
    return None


async def grab_banner(host: str, port: int, timeout: float = 3.0) -> ServiceInfo:
    """Attempt a TCP connect to host:port and extract a banner / version string."""
    try:
        if port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
    except Exception:
        return ServiceInfo(
            port=port,
            protocol="tcp",
            state="closed",
            banner=None,
            service_guess=_guess_service(port, None),
            version_string=None,
        )

    banner_bytes = b""
    try:
        if port in (80, 8080, 443, 8443):
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            banner_bytes = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        elif port == 3306:
            banner_bytes = await asyncio.wait_for(reader.read(64), timeout=timeout)
        else:
            # Try reading a greeting first; if nothing, send a probe
            try:
                banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            except TimeoutError:
                writer.write(b"\r\n")
                await writer.drain()
                banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=timeout)
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if port == 3306 and len(banner_bytes) >= 6:
        # MySQL handshake: version string starts at byte 5, null-terminated
        raw = banner_bytes[5:]
        null_pos = raw.find(b"\x00")
        version_str = raw[:null_pos].decode("latin-1", errors="replace") if null_pos >= 0 else None
        mysql_banner = f"MySQL {version_str}" if version_str else "MySQL"
        return ServiceInfo(
            port=port,
            protocol="tcp",
            state="open",
            banner=mysql_banner,
            service_guess="mysql",
            version_string=version_str,
        )

    banner_text: str | None = None
    if banner_bytes:
        banner_text = banner_bytes.decode("latin-1", errors="replace").strip()

    version_string = _parse_version(port, banner_text) if banner_text else None
    service_guess = _guess_service(port, banner_text)

    return ServiceInfo(
        port=port,
        protocol="tcp",
        state="open",
        banner=banner_text,
        service_guess=service_guess,
        version_string=version_string,
    )

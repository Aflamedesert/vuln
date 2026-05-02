from __future__ import annotations

from scanner.core.banner_grabber import _guess_service, _parse_version


def test_service_guess_ssh_from_banner() -> None:
    # Port not in well-known map; banner detection must kick in
    result = _guess_service(9922, "SSH-2.0-OpenSSH_8.2")
    assert result == "ssh"


def test_service_guess_ssh_from_port() -> None:
    result = _guess_service(22, None)
    assert result == "ssh"


def test_service_guess_http_from_port() -> None:
    result = _guess_service(80, "Server: Apache/2.4.51")
    assert result == "http"


def test_service_guess_http_from_banner() -> None:
    # Banner contains "http" → banner-based detection
    result = _guess_service(9999, "HTTP/1.1 200 OK")
    assert result == "http"


def test_version_extraction_openssh() -> None:
    version = _parse_version(22, "SSH-2.0-OpenSSH_8.2")
    assert version is not None
    assert "8.2" in version


def test_version_extraction_nginx() -> None:
    # Port 80 uses the Server: header pattern
    version = _parse_version(80, "Server: nginx/1.18.0")
    assert version is not None
    assert "1.18.0" in version


def test_version_extraction_ftp() -> None:
    version = _parse_version(21, "220 vsftpd 3.0.3")
    assert version is not None


def test_version_extraction_unknown_port_no_crash() -> None:
    # Should not raise even on an unexpected banner
    _parse_version(9999, "some random banner text")


def test_service_guess_ftp_from_banner() -> None:
    result = _guess_service(9999, "220 FTP Server ready")
    assert result == "ftp"


def test_service_guess_smtp_from_banner() -> None:
    result = _guess_service(9999, "220 smtp.example.com ESMTP Postfix")
    assert result == "smtp"


def test_service_guess_mysql_from_banner() -> None:
    result = _guess_service(9999, "MySQL 8.0.32")
    assert result == "mysql"


def test_service_guess_none_when_no_banner_and_unknown_port() -> None:
    result = _guess_service(9999, None)
    assert result is None


def test_grab_banner_connection_refused() -> None:
    import asyncio
    from unittest.mock import AsyncMock, patch

    from scanner.core.banner_grabber import grab_banner

    async def _fail(*args: object, **kwargs: object) -> object:
        raise ConnectionRefusedError("refused")

    with patch("asyncio.open_connection", _fail):
        info = asyncio.run(grab_banner("127.0.0.1", 9988, timeout=1.0))

    assert info.state == "closed"
    assert info.banner is None

from __future__ import annotations

import re
import sqlite3

from packaging.version import InvalidVersion, Version

VENDOR_ALIASES: dict[str, str] = {
    "openbsd": "openbsd",
    "apache": "apache",
    "nginx": "nginx",
    "php": "php",
    "mysql": "mysql",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "openssh": "openbsd",
    "microsoft": "microsoft",
    "iis": "microsoft",
}

PRODUCT_ALIASES: dict[str, str] = {
    "httpd": "http_server",
    "openssh": "openssh",
    "iis": "iis",
    "tomcat": "tomcat",
    "redis": "redis",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "apache": "http_server",
}

_EXTRACT_PATTERNS: list[str] = [
    r"(?P<vendor>\w+)\s+(?P<product>\w+)[/\s](?P<version>[\d][\d.]+)",
    r"(?P<product>\w+)/(?P<version>[\d][\d.]+)",
    r"(?P<product>\w+)\s+(?P<version>[\d][\d.]+)",
]


def normalize_banner(banner: str) -> str:
    """Lowercase, replace /\\-_ with space, collapse whitespace, strip."""
    lowered = banner.lower()
    replaced = re.sub(r"[/\\\-_]", " ", lowered)
    return re.sub(r"\s+", " ", replaced).strip()


def extract_components(banner: str) -> dict[str, str | None]:
    """Try regex patterns in order; return dict with vendor/product/version keys."""
    normalized = normalize_banner(banner)
    for pat in _EXTRACT_PATTERNS:
        m = re.search(pat, normalized)
        if m:
            gd = m.groupdict()
            return {
                "vendor": gd.get("vendor"),
                "product": gd.get("product"),
                "version": gd.get("version"),
            }
    return {"vendor": None, "product": None, "version": None}


def build_cpe_uri(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def version_in_range(
    version: str,
    start_inc: str | None,
    start_exc: str | None,
    end_inc: str | None,
    end_exc: str | None,
) -> bool:
    """Return True if *version* falls within the CPE match range."""
    try:
        v = Version(version)
    except InvalidVersion:
        return False

    if start_inc is not None:
        try:
            if v < Version(start_inc):
                return False
        except InvalidVersion:
            pass

    if start_exc is not None:
        try:
            if v <= Version(start_exc):
                return False
        except InvalidVersion:
            pass

    if end_inc is not None:
        try:
            if v > Version(end_inc):
                return False
        except InvalidVersion:
            pass

    if end_exc is not None:
        try:
            if v >= Version(end_exc):
                return False
        except InvalidVersion:
            pass

    return True


def match_banner(
    banner: str,
    conn: sqlite3.Connection,
) -> tuple[str | None, float, str]:
    """Return (cpe_uri, confidence, match_method) for a given banner string."""
    comps = extract_components(banner)
    vendor = comps.get("vendor")
    product = comps.get("product")
    version = comps.get("version")

    if not product or not version:
        return None, 0.0, "none"

    # Try exact match first
    raw_vendor = vendor or product
    cpe = build_cpe_uri(raw_vendor, product, version)
    row = conn.execute(
        "SELECT 1 FROM cpe_matches WHERE cpe_uri = ? LIMIT 1", (cpe,)
    ).fetchone()
    if row:
        return cpe, 0.95, "exact"

    # Try alias substitution
    aliased_vendor = VENDOR_ALIASES.get(raw_vendor, raw_vendor)
    aliased_product = PRODUCT_ALIASES.get(product, product)
    alias_cpe = build_cpe_uri(aliased_vendor, aliased_product, version)
    if alias_cpe != cpe:
        row = conn.execute(
            "SELECT 1 FROM cpe_matches WHERE cpe_uri = ? LIMIT 1", (alias_cpe,)
        ).fetchone()
        if row:
            return alias_cpe, 0.80, "alias"

    # Prefix search on product+version for fuzzy matching
    prefix = f"cpe:2.3:a:%:{aliased_product}:{version}:%"
    row = conn.execute(
        "SELECT cpe_uri FROM cpe_matches WHERE cpe_uri LIKE ? LIMIT 1", (prefix,)
    ).fetchone()
    if row:
        return str(row[0]), 0.80, "alias"

    return None, 0.0, "none"

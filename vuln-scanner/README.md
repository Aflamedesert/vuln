# vuln-scanner

A portfolio-grade Python network vulnerability scanner with CVE enrichment, diff tracking, and multi-format reporting.

> **Ethical Use Warning**: This tool is intended for use only on networks and systems you own or have explicit written permission to test. Unauthorized scanning is illegal and unethical. The authors accept no responsibility for misuse.

---

## Prerequisites

- Docker and Docker Compose (recommended)
- OR: Python 3.11+, `libpcap-dev`, `tcpdump`, and `CAP_NET_RAW` capability

## Quick Start

```bash
# Build and start the scanner container
docker compose build

# Run a scan against the bundled target
docker compose run scanner vuln-scanner scan --target 172.16.0.0/24

# Start the vulnerable target for local testing
docker compose up target
```

## Development Setup

```bash
# Create a virtual environment and install with dev extras
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Lint
ruff check scanner/

# Type check
mypy scanner/

# Tests
pytest --cov=scanner
```

---

## Architecture

The scanner is composed of three cooperating layers:

1. **Port scanner** (`scanner/core/port_scanner.py`) — async wrapper around Scapy SYN probes, with automatic TCP-connect fallback when `CAP_NET_RAW` is unavailable.
2. **Banner grabber** (`scanner/core/banner_grabber.py`) — `asyncio.open_connection` probes per open port with protocol-specific parsing (FTP, SSH, SMTP, HTTP/S, MySQL, generic).
3. **OS fingerprinter** (`scanner/core/os_fingerprint.py`) — TTL + TCP-window table lookup returning an OS guess and confidence score.

Results flow: `cli.scan` → `scan_host` → `grab_banner` (per open port) → `fingerprint_os` → Rich table.

## Usage

```bash
# Scan localhost high ports (no root needed — TCP connect fallback)
vuln-scanner scan --target 127.0.0.1 --ports 8000-8080

# SYN scan a subnet (requires CAP_NET_RAW / root or Docker)
sudo vuln-scanner scan --target 192.168.1.0/24 --ports 22,80,443,3306

# Scan with custom timeout and concurrency
vuln-scanner scan -t 10.0.0.1 -p 1-1024 --timeout 1.5 --concurrency 200

# Save results for later diffing / reporting (Phase 3+)
vuln-scanner scan -t 10.0.0.1 --output-json results.json
```

## CVE Database

```bash
# Sync NVD feeds for the last two years (default)
vuln-scanner sync-db

# Sync a specific year
vuln-scanner sync-db --year 2021

# Use a custom database path
vuln-scanner sync-db --db-path /opt/scanner/cve.db
```

After syncing, `scan` automatically enriches results with CVE counts and severity:

```bash
# Scan and show CVE matches alongside port results
vuln-scanner scan --target 192.168.1.10 --ports 22,80,443,3306

# Full subnet scan with CVE enrichment
sudo vuln-scanner scan --target 10.0.0.0/24 --ports 1-1024 --concurrency 200
```

## Output Formats

[placeholder — coming in Phase 5]

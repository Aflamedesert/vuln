# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repo has two layers:
- **Root** (`/`): Minimal `uv`-managed stub (`main.py` prints "Hello from vuln!"). Python 3.11+.
- **Scanner** (`vuln-scanner/`): The real implementation — a portfolio-grade Python CLI network vulnerability scanner. See `vuln-scanner/CLAUDE.md` for detailed architecture and conventions.

## Commands

### Root stub (uv)

```bash
uv sync --dev
uv run python main.py
uv run pytest path/to/test_file.py::test_name
```

### Scanner package (vuln-scanner/)

```bash
# Install (requires libpcap-dev and tcpdump on Linux)
pip install -e ".[dev]"

# CLI
vuln-scanner --help
vuln-scanner scan --target 192.168.1.0/24 --ports 22,80,443 --output-json results.json
vuln-scanner sync-db
vuln-scanner diff old.json new.json --output-html diff.html
vuln-scanner report results.json --output-html report.html --output-pdf report.pdf

# Lint + type check
ruff check scanner/ && mypy scanner/

# Tests (unit only — no network or raw-socket required)
pytest tests/unit/ -v

# Tests (full suite with coverage — must stay >= 80%)
pytest tests/ --cov=scanner --cov-report=term-missing -v

# Single test file or test function
pytest tests/unit/test_os_fingerprint.py -v
pytest tests/unit/test_port_scanner.py::test_parse_port_range_mixed -v
```

### Docker (scanner, requires CAP_NET_RAW)

```bash
docker compose run scanner vuln-scanner scan --target 192.168.1.1 --ports 22,80,443
```

## Architecture

The scanner is a three-layer pipeline inside `vuln-scanner/scanner/`:

1. **Core** (`core/`): Port scanning (Scapy SYN → TCP connect fallback), async banner grabbing, TTL/window OS fingerprinting.
2. **Enrichment** (`enrichment/`): NVD 2.0 API sync into local SQLite (`~/.vuln-scanner/cve.db`), CPE matching from banners, CVE lookup with CVSS scoring.
3. **Reporting** (`reporting/`): `ScanReport` dataclass, JSON serialization, Rich CLI tables/panels, Jinja2 HTML template, WeasyPrint PDF.
4. **Diff** (`diff/`): Structural diff between two scan JSON files (`diff_scans`); SQLite scan history (`scan_history` table in the CVE DB).

Entry point: `scanner/cli.py` (Click group) → `scanner/config.py` (`ScanConfig` dataclass).

## Testing

Tests live in `vuln-scanner/tests/`. The suite is split into `unit/` (no network, no raw sockets) and `integration/` (spins up a local TCP echo server on `127.0.0.1:19922`).

Key shared fixtures in `tests/conftest.py`:
- `mem_db` — in-memory SQLite with full schema
- `sample_cve` — `mem_db` seeded with CVE-2021-44228 (Log4Shell, CVSS 10.0)
- `syn_ack_linux/windows/cisco` — Scapy packets for OS fingerprint tests

CI (`.github/workflows/test.yml`) runs on every push and PR: installs `libpcap-dev`, runs `pytest tests/ --cov=scanner --cov-report=xml -v`, enforces ≥ 80% coverage, then uploads to Codecov.

## Phase Status

| Phase | Feature | Status |
|---|---|---|
| 1 | Scaffolding | Done |
| 2 | Port scan + banner grab + OS fingerprint | Done |
| 3 | CVE enrichment (NVD sync, CPE match, CVSS) | Done |
| 4 | Full test suite + CI workflow | Done |
| 5 | Reporting engine + diff + scan history | Done |

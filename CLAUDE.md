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
vuln-scanner scan --target 192.168.1.0/24 --ports 22,80,443 --output results.json
vuln-scanner sync-db
vuln-scanner diff old.json new.json   # Phase 4 — not yet implemented
vuln-scanner report results.json       # Phase 5 — not yet implemented

# Lint + type check
ruff check scanner/ && mypy scanner/

# Tests
pytest --cov=scanner
```

### Docker (scanner, requires CAP_NET_RAW)

```bash
docker compose run scanner vuln-scanner scan --target 192.168.1.1 --ports 22,80,443
```

## Architecture

The scanner is a three-layer pipeline inside `vuln-scanner/scanner/`:

1. **Core** (`core/`): Port scanning (Scapy SYN → TCP connect fallback), async banner grabbing, TTL/window OS fingerprinting.
2. **Enrichment** (`enrichment/`): NVD 2.0 API sync into local SQLite (`~/.vuln-scanner/cve.db`), CPE matching from banners, CVE lookup with CVSS scoring.
3. **Reporting / Diff** (`reporting/`, `diff/`): Phase 5 and Phase 4 placeholders respectively.

Entry point: `scanner/cli.py` (Click group) → `scanner/config.py` (`ScanConfig` dataclass).

## Phase Status

| Phase | Feature | Status |
|---|---|---|
| 1 | Scaffolding | Done |
| 2 | Port scan + banner grab + OS fingerprint | Done |
| 3 | CVE enrichment (NVD sync, CPE match, CVSS) | Done |
| 4 | Scan diff | Next |
| 5 | JSON/HTML/PDF reporting | Pending |

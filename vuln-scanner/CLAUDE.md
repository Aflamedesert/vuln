# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

`vuln-scanner` is a portfolio-grade Python CLI tool for network vulnerability scanning. It performs TCP port scanning, enriches results with NVD CVE data, tracks changes between scans, and produces JSON/HTML/PDF reports. Phase 1 is scaffolding only; subcommands print "[Phase N] not yet implemented".

## Conventions

- **Type hints everywhere**: all functions must be fully annotated. Mypy runs in strict mode.
- **No `print()`**: use `rich` for console output or `click.echo` for simple CLI feedback.
- **Ruff** enforces line-length=100 and rule sets E, F, I, UP. Run `ruff check scanner/` before committing.
- **No external imports in `config.py`**: only `dataclasses` and `__future__` are allowed there.
- Entry point is `vuln-scanner` → `scanner.cli:cli` (Click group).

## Module Responsibilities

| Module | Responsibility |
|---|---|
| `scanner/cli.py` | Click CLI — argument parsing only, delegates to other modules |
| `scanner/config.py` | `ScanConfig` dataclass — single source of truth for all scan parameters |
| `scanner/core/` | Port scanning engine (TCP SYN/connect), service fingerprinting |
| `scanner/enrichment/` | NVD CVE lookup and local SQLite cache (`cve.db`) |
| `scanner/reporting/` | Jinja2 → HTML and WeasyPrint → PDF report generation |
| `scanner/diff/engine.py` | `diff_scans` — structural diff between two scan JSON files |
| `scanner/diff/history.py` | SQLite scan history (`scan_history` table in CVE DB) |
| `scanner/reporting/models.py` | `ScanReport` dataclass + `build_report` aggregator |
| `scanner/reporting/json_report.py` | JSON serialization/deserialization of `ScanReport` |
| `scanner/reporting/cli_report.py` | Rich console tables/panels |
| `scanner/reporting/html_report.py` | Jinja2 → HTML via `templates/report.html.j2` |
| `scanner/reporting/pdf_report.py` | WeasyPrint → PDF from rendered HTML |
| `scanner/plugins/base.py` | `PluginFinding` dataclass, `BasePlugin` ABC, `discover_plugins()` runtime discovery |
| `scanner/plugins/http_headers.py` | Checks missing HTTP security headers (XFO, CSP, XCTO, HSTS) |
| `scanner/plugins/ssl_check.py` | Checks weak TLS version, cert expiry, self-signed cert |
| `scanner/enrichment/epss.py` | Downloads EPSS CSV.GZ, upserts into `epss_scores` table, `get_epss_score()` |

## Running Locally

```bash
# Install (needs libpcap-dev and tcpdump on Linux)
pip install -e ".[dev]"

# CLI entry point
vuln-scanner --help

# Lint + type check
ruff check scanner/ && mypy scanner/

# Tests with coverage
pytest --cov=scanner
```

## Scanning Engine Internals

**Port scanner** (`scanner/core/port_scanner.py`):
- `_syn_probe` is a blocking function that runs inside a `ThreadPoolExecutor`; it is driven by `_async_syn_probe` which applies an `asyncio.Semaphore(config.concurrency)` limit.
- If Scapy raises `PermissionError` (no raw-socket capability), the code silently falls back to `_tcp_connect_probe` — a plain `socket.connect_ex` that reports open/closed but yields no TTL or window data.
- `parse_port_range` accepts mixed comma+range syntax: `"22,80,8000-8080"`.
- `expand_targets` handles a single IP, a CIDR (via `ipaddress.ip_network`), or a bare hostname.

**Banner grabber** (`scanner/core/banner_grabber.py`):
- Fully async via `asyncio.open_connection`; HTTPS ports use `ssl.create_default_context()` with verification disabled.
- Port-specific read strategies: passive read for FTP/SSH/SMTP, active HTTP HEAD probe, 64-byte handshake read for MySQL.
- `_parse_version` applies port-appropriate regexes to extract a version string from the raw banner.

**OS fingerprinter** (`scanner/core/os_fingerprint.py`):
- Single lookup table (`_FINGERPRINTS`, a `list[_FingerprintEntry]`) — no if/elif chains.
- Confidence tiers: TTL+window match → entry confidence; TTL-only → 0.6; window-only → 0.4; no match → `(None, 0.0)`.

**Data model** (`scanner/core/models.py`):
- `ServiceInfo` — per-port result; state is always one of `"open"`, `"closed"`, `"filtered"`.
- `ScanResult` — per-host result; `services` list is populated in `scan_host`, banners are merged in `cli.scan`.
- `CVEMatch`, `EnrichedService`, `EnrichedScanResult` — Phase 3 enrichment wrappers; never mutate `ServiceInfo` or `ScanResult` directly.

## CVE Enrichment Internals

**Database** (`scanner/enrichment/db.py`):
- `get_db(path)` expands `~`, creates parent dirs, opens SQLite with WAL mode and foreign keys on.
- Three tables: `cves` (PK on `cve_id`), `cpe_matches` (indexed by `cpe_uri`), `sync_log`.
- `upsert_cve` / `upsert_cpe_match` use `INSERT OR REPLACE`; callers must commit in batches.

**NVD sync** (`scanner/enrichment/nvd_sync.py`):
- Uses the NVD 2.0 REST API (`/rest/json/cves/2.0`); the legacy 1.1 JSON feeds were retired in March 2023.
- Splits each year into 90-day windows (NVD enforces a 120-day max per request), paginates at 2000 results/page, commits every 500 records.
- CVSS v3 is preferred; v2 is used as fallback when v3 is absent.
- Recurses into `configurations.nodes[].children[]` to collect all `cpe_match` entries.

**CPE matcher** (`scanner/enrichment/cpe_matcher.py`):
- `normalize_banner` → lowercase, punctuation→space, collapse whitespace.
- `extract_components` tries three regex patterns in order (vendor+product+version, product/version, product version).
- Match pipeline: exact CPE URI lookup → alias substitution → prefix LIKE search.
- Confidence: exact=0.95, alias/prefix=0.80, no match=0.0.

**CVE lookup** (`scanner/enrichment/cve_lookup.py`):
- `enrich_service` calls `match_banner`, queries `cpe_matches`, filters by `version_in_range`, fetches full CVE records, sorts by CVSS score descending.
- `enrich_results` wraps a list of `ScanResult` objects and returns `list[EnrichedScanResult]`.

## Testing

### Test layout

```
tests/
├── conftest.py               shared fixtures (mem_db, sample_cve, syn_ack_*)
├── unit/
│   ├── test_banner_grabber.py   _guess_service, _parse_version, connection errors
│   ├── test_cli.py              Click CliRunner tests for all commands
│   ├── test_cpe_matcher.py      normalize_banner, extract_components, match_banner
│   ├── test_cve_lookup.py       enrich_service, enrich_results, version range filter
│   ├── test_cvss_scorer.py      score_to_severity boundary cases
│   ├── test_db.py               get_db, log_sync, schema idempotency
│   ├── test_nvd_sync.py         _parse_cve, _parse_cpe_matches, _date_windows, sync_nvd
│   ├── test_os_fingerprint.py   TTL+window, TTL-only, window-only, unknown
│   ├── test_port_scanner.py     parse_port_range, expand_targets, _tcp_connect_probe
│   ├── test_version_range.py    version_in_range boundary cases
│   ├── test_diff_engine.py      diff_scans structural diff cases
│   └── test_json_report.py      ScanReport serialization round-trips
└── integration/
    ├── test_db_sync.py           create_tables idempotency, upsert CVE/CPE
    └── test_scan_pipeline.py     live echo server at 127.0.0.1:19922
```

### Running tests

```bash
# All tests with coverage (must be >= 80%)
pytest tests/ --cov=scanner --cov-report=term-missing -v

# Unit tests only (no network or raw-socket requirements)
pytest tests/unit/ -v

# Integration tests (spin up a local TCP echo server)
pytest tests/integration/ -v
```

### Key fixtures (tests/conftest.py)

| Fixture | Description |
|---|---|
| `mem_db` | In-memory SQLite connection with full schema |
| `sample_cve` | `mem_db` populated with CVE-2021-44228 (Log4Shell, CVSS 10.0) |
| `syn_ack_linux` | Scapy IP(ttl=64)/TCP(flags="SA", window=65535) packet |
| `syn_ack_windows` | Scapy IP(ttl=128)/TCP(flags="SA", window=8192) packet |
| `syn_ack_cisco` | Scapy IP(ttl=255)/TCP(flags="SA", window=4128) packet |

### Mocking strategy

- **CLI tests** use Click's `CliRunner` and mock `scan_host`, `grab_banner`, `fingerprint_os`, `enrich_results` as `AsyncMock`/regular mocks so no network calls happen.
- **nvd_sync tests** patch `_fetch_page` to return canned JSON; `time.sleep` is also patched to keep tests fast.
- **Integration tests** start a real `socket.socket` echo server in a background thread; `scan_host` and `grab_banner` hit it via TCP connect (no `CAP_NET_RAW` required).

## Plugin System

Plugins live in `scanner/plugins/`. `discover_plugins()` in `base.py` uses `pkgutil.iter_modules` to find every module in that package (excluding `base` itself), imports it, and collects concrete `BasePlugin` subclasses.

**Contract for a valid plugin:**
- Define `name: str` and `description: str` as class attributes.
- Implement `applies_to(service: ServiceInfo) -> bool` — called for every open service; return `True` to opt in.
- Implement `run(service: ServiceInfo, host: str) -> list[PluginFinding]` — called only when `applies_to` returned `True`; must not raise (exceptions are swallowed by the CLI runner and logged as warnings).
- Place the file in `scanner/plugins/<name>.py`; no registration step is needed.

**`PluginFinding` fields:** `plugin_name`, `title`, `description`, `severity` (one of `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`), `evidence` (optional string).

**Circular import guard:** `PluginFinding` is in `plugins/base.py` which imports `ServiceInfo` from `core/models.py`. `EnrichedService` (in `core/models.py`) has a `plugin_findings: list[PluginFinding]` field. The circular import is broken with a `TYPE_CHECKING` guard — safe because `from __future__ import annotations` makes all annotations lazy strings never evaluated at runtime.

## EPSS Scoring

`scanner/enrichment/epss.py` downloads the daily EPSS CSV.GZ from `https://epss.cyentia.com/epss_scores-current.csv.gz`. The CSV has columns `cve,epss,percentile` (with a leading `#metadata` comment line) and is upserted into the `epss_scores` table with PK `(cve_id, score_date)`.

- `fetch_epss(db_path)` — downloads, decompresses, parses, and upserts; shows a Rich progress bar; returns row count.
- `get_epss_score(cve_id, conn)` — returns `(probability, percentile)` or `None`; always picks the most recent `score_date` if multiple exist.
- Called from `cve_lookup.enrich_service` after each `CVEMatch` is built; populates `CVEMatch.epss_probability` and `CVEMatch.epss_percentile`.
- Activated via `vuln-scanner sync-db --epss`.

## Known Constraints

- Raw socket operations (`scan`) require `CAP_NET_RAW`. Run inside Docker (`docker compose run scanner …`) or with `sudo` locally.
- `sync-db` writes to `~/.vuln-scanner/cve.db` by default; the directory must be writable.
- `weasyprint` has system-level font/CSS dependencies; the Dockerfile installs them via `libpcap-dev` and `tcpdump` (additional GTK/Pango deps may be needed for full PDF support in later phases).

## Known Limitations & Future Work

- **UDP scanning** — only TCP is supported. DNS (53), SNMP (161/162), and NTP (123) are not scanned.
- **CPE matching accuracy** — the regex extraction + alias pipeline is brittle for unusual vendor names or non-standard banner strings. An embedding-based matcher would improve true positive rates.
- **Version range edge cases** — `version_in_range` splits on `.` and compares tuples; it mishandles pre-release suffixes (e.g. `1.0.0-rc1`). Switch to `packaging.version.Version` when precision matters.
- **Serial plugin execution** — plugins run one at a time per service. Wrapping the runner in `asyncio.gather` with a concurrency semaphore would speed up scans against targets with many TLS/HTTP services.
- **Plugin findings not diffed** — the diff engine compares CVEs and ports but ignores `plugin_findings`. Extending `DiffReport` to include plugin-finding deltas would make change tracking more useful.
- **No authentication support** — the scanner has no mechanism to supply credentials to authenticated services (SSH, SNMP v3, HTTP Basic). Authenticated scanning could surface additional vulnerabilities not visible from the outside.

# vuln-scanner User Manual

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Commands](#commands)
   - [scan](#scan)
   - [sync-db](#sync-db)
   - [diff](#diff)
   - [report](#report)
5. [Port Specification](#port-specification)
6. [Output Formats](#output-formats)
7. [CVE Database](#cve-database)
8. [EPSS Exploit Scoring](#epss-exploit-scoring)
9. [Plugins](#plugins)
10. [Scan History and Diff](#scan-history-and-diff)
11. [Running with Docker](#running-with-docker)
12. [Ethical Use](#ethical-use)

---

## Overview

`vuln-scanner` is a Python CLI tool for network vulnerability scanning. It sends raw TCP SYN probes, grabs service banners asynchronously, fingerprints the OS from TTL and TCP window values, enriches results against a local offline copy of the NVD CVE database, and produces JSON, HTML, and PDF reports.

It does not wrap `nmap` or any other external scanner.

**Core pipeline for each scan:**

```
scan_host (SYN / TCP-connect)
    → grab_banner (async, protocol-aware)
    → fingerprint_os (TTL + window lookup)
    → enrich_results (CPE match → CVE lookup → EPSS scoring)
    → discover_plugins → plugin.run() per open service
    → build_report → JSON / HTML / PDF / console
```

---

## Installation

### Requirements

- Python 3.11+
- Linux: `libpcap-dev` and `tcpdump` (for raw socket support)
- `CAP_NET_RAW` capability or root (for SYN probes; see [Running with Docker](#running-with-docker))

### Local installation

```bash
cd vuln-scanner/
pip install -e ".[dev]"
```

This installs the `vuln-scanner` CLI entry point and all dependencies (Scapy, Click, Rich, Jinja2, WeasyPrint, requests).

### Verify installation

```bash
vuln-scanner --help
```

---

## Quick Start

```bash
# 1. Sync the CVE database (do this once, then periodically)
vuln-scanner sync-db

# 2. Scan a host (raw SYN — requires CAP_NET_RAW or sudo)
sudo vuln-scanner scan --target 192.168.1.10 --ports 22,80,443 --output-json results.json

# 3. Scan without elevated privileges (TCP-connect fallback, no TTL/window data)
vuln-scanner scan --target 192.168.1.10 --ports 80,8080

# 4. Generate an HTML report from a saved scan
vuln-scanner report results.json --output-html report.html
```

---

## Commands

### scan

Runs a full scan against a target host or network range.

```
vuln-scanner scan [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--target TEXT` | *(required)* | IP address, hostname, or CIDR range (e.g. `192.168.1.0/24`) |
| `--ports TEXT` | `1-1024` | Port specification — see [Port Specification](#port-specification) |
| `--timeout FLOAT` | `2.0` | Per-probe timeout in seconds |
| `--concurrency INT` | `100` | Maximum simultaneous probes |
| `--output-json PATH` | — | Write full scan report to a JSON file |
| `--output-html PATH` | — | Write HTML report to a file |
| `--output-pdf PATH` | — | Write PDF report to a file |

**What happens during a scan:**

1. **Port scan** — Sends a TCP SYN packet to each port via Scapy. If `CAP_NET_RAW` is unavailable, falls back silently to `socket.connect_ex` (open/closed detection only; no TTL or window data).
2. **Banner grabbing** — Asynchronously connects to each open port and reads service banners. Uses protocol-specific strategies: passive read for FTP/SSH/SMTP, an HTTP HEAD request for web ports, a 64-byte handshake read for MySQL. Extracts a version string where possible.
3. **OS fingerprinting** — Matches the response TTL and TCP window size against a lookup table. Reports OS guess and confidence level (TTL + window match ≈ 0.95, TTL-only ≈ 0.60, window-only ≈ 0.40).
4. **CVE enrichment** — If a CVE database exists at `~/.vuln-scanner/cve.db`, maps each banner to a CPE URI and retrieves matching CVEs sorted by CVSS score descending. Attaches EPSS probability and percentile to each CVE if available.
5. **Plugin execution** — Runs all discovered plugins against each open service. Built-in plugins check HTTP security headers and TLS/certificate health.
6. **Reporting** — Prints a Rich console summary and writes any requested output files. Saves the scan to SQLite history.

**Examples:**

```bash
# Scan a single host, all common ports
sudo vuln-scanner scan --target 10.0.0.5 --ports 1-1024

# Scan a /24 network, specific ports, save everything
sudo vuln-scanner scan \
  --target 192.168.1.0/24 \
  --ports 22,80,443,8080-8443 \
  --timeout 3.0 \
  --concurrency 50 \
  --output-json results.json \
  --output-html results.html \
  --output-pdf results.pdf

# Low-privilege scan (TCP connect, no root)
vuln-scanner scan --target example.internal --ports 80,443,8080
```

---

### sync-db

Downloads CVE data from the NVD 2.0 API and caches it in a local SQLite database. Run this once before your first scan, and periodically (weekly or monthly) to keep the database current.

```
vuln-scanner sync-db [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--db-path PATH` | `~/.vuln-scanner/cve.db` | Path to the CVE database |
| `--year INTEGER` | Current + prior year | NVD year(s) to sync; repeatable |
| `--epss` | off | Also download daily EPSS exploit-probability scores |

The NVD dataset is large. Initial sync for two years typically downloads tens of thousands of CVEs and takes several minutes (the NVD API enforces a rate limit of 5 requests per 30 seconds). Subsequent syncs are faster because only recent entries need updating.

**Examples:**

```bash
# Default sync (current year + prior year)
vuln-scanner sync-db

# Sync a specific year
vuln-scanner sync-db --year 2023

# Sync multiple years
vuln-scanner sync-db --year 2022 --year 2023 --year 2024

# Sync CVEs and EPSS scores
vuln-scanner sync-db --epss

# Use a non-default database path
vuln-scanner sync-db --db-path /opt/vuln-scanner/cve.db
```

---

### diff

Compares two scan results and reports what changed: new open ports, closed ports, new CVEs, and resolved CVEs.

```
vuln-scanner diff [OPTIONS] [SCAN_A] [SCAN_B]
```

Scans can be specified as JSON file paths or loaded from scan history by label.

| Argument/Option | Description |
|---|---|
| `SCAN_A` | Path to the first (older) scan JSON file |
| `SCAN_B` | Path to the second (newer) scan JSON file |
| `--label-a TEXT` | Load scan A from history by label instead of a file |
| `--label-b TEXT` | Load scan B from history by label instead of a file |
| `--output-json PATH` | Write diff report to a JSON file |
| `--output-html PATH` | Write diff report to an HTML file |

**Diff output includes:**

- **New ports** — ports that are open in scan B but were not open in scan A
- **Closed ports** — ports that were open in scan A but are not open in scan B
- **New CVEs** — CVEs present in scan B that were not in scan A, with severity
- **Resolved CVEs** — CVEs that disappeared between scans (service version changed, port closed, etc.)
- **Summary counts** — new CRITICAL and HIGH CVE totals for quick triage

**Examples:**

```bash
# Compare two scan files
vuln-scanner diff baseline.json current.json

# Save diff as HTML
vuln-scanner diff baseline.json current.json --output-html changes.html

# Compare using scan history labels
vuln-scanner diff --label-a "baseline-2024-01" --label-b "scan-2024-06"
```

---

### report

Regenerates an HTML or PDF report from a previously saved scan JSON file. Useful when you want to share a report without re-running the scan.

```
vuln-scanner report [OPTIONS] SCAN_JSON
```

| Argument/Option | Description |
|---|---|
| `SCAN_JSON` | Path to a scan JSON file produced by `scan --output-json` |
| `--output-html PATH` | Write HTML report (at least one output is required) |
| `--output-pdf PATH` | Write PDF report (at least one output is required) |

**Example:**

```bash
vuln-scanner report results.json --output-html report.html --output-pdf report.pdf
```

---

## Port Specification

The `--ports` argument accepts comma-separated ports and hyphen-separated ranges, in any combination:

| Syntax | Meaning |
|---|---|
| `80` | Single port |
| `22,80,443` | Comma-separated list |
| `8000-8080` | Inclusive range |
| `22,80,8000-8080` | Mixed |

**Examples:**

```bash
--ports 22                  # SSH only
--ports 22,80,443           # SSH, HTTP, HTTPS
--ports 1-1024              # All well-known ports (default)
--ports 22,80,8000-8080     # Mixed syntax
```

---

## Output Formats

Every scan produces a console summary. Additional formats are opt-in.

### Console (always on)

Rich tables and panels printed to the terminal. Shows open ports, service guesses, version strings, OS fingerprint, CVE count by severity, and plugin findings per host.

### JSON (`--output-json`)

A serialized `ScanReport` containing the full scan: timestamps, host count, severity tallies, and per-host data including all `EnrichedService` records, CVE matches, and plugin findings. This file is the input to `diff` and `report`.

### HTML (`--output-html`)

A self-contained HTML file rendered from a Jinja2 template. Includes all scan data in a readable format suitable for sharing or archiving.

### PDF (`--output-pdf`)

A PDF generated from the HTML output via WeasyPrint. Requires system-level font and CSS dependencies (installed automatically in the Docker image).

---

## CVE Database

The CVE database is a local SQLite file (default: `~/.vuln-scanner/cve.db`) populated by `sync-db`. It stores:

- **`cves`** — CVE ID, description, CVSS v3 score (v2 as fallback), severity, and published date.
- **`cpe_matches`** — CPE URI patterns and version ranges linking products to CVEs.
- **`epss_scores`** — Daily EPSS probability and percentile per CVE.
- **`sync_log`** — Record of each sync operation.
- **`scan_history`** — Serialized scan results saved automatically after each `scan` run.

**CPE matching pipeline:**

When enriching a scan, the scanner maps each service banner to a CVE by:

1. Normalising the banner (lowercasing, stripping punctuation).
2. Extracting vendor, product, and version with regex patterns.
3. Looking up an exact CPE URI in the database.
4. If no exact match, trying known product aliases.
5. If still no match, trying a prefix `LIKE` search.

Each match carries a confidence score: exact = 0.95, alias/prefix = 0.80. A confidence of 0.0 means no CPE was found and no CVEs will be returned for that service.

---

## EPSS Exploit Scoring

EPSS (Exploit Prediction Scoring System) gives each CVE a probability (0–1) that it will be exploited in the wild in the next 30 days, plus a percentile rank among all CVEs.

CVSS tells you how severe a vulnerability *could* be. EPSS tells you how likely it is to be exploited *now*. Using both together helps prioritise patching: a CVSS 9.8 with EPSS 0.002 (bottom 20%) is lower priority than a CVSS 7.5 with EPSS 0.85 (top 5%).

**Enabling EPSS:**

```bash
vuln-scanner sync-db --epss
```

This downloads the current-day EPSS CSV from the FIRST project, parses it, and upserts scores into the database. Re-run daily or weekly to keep scores current.

Once EPSS data is present, every `CVEMatch` in scan output includes `epss_probability` and `epss_percentile` fields alongside the CVSS score.

---

## Plugins

Plugins extend the scanner with per-service checks that run after the core scan pipeline. Two plugins ship built-in.

### HTTP Security Headers (`http_headers`)

Applies to: services on HTTP or HTTPS ports.

Sends an HTTP HEAD request and checks for the presence of security-relevant response headers:

| Header | Missing severity |
|---|---|
| `X-Frame-Options` | MEDIUM |
| `Content-Security-Policy` | MEDIUM |
| `X-Content-Type-Options` | LOW |
| `Strict-Transport-Security` | HIGH (HTTPS only) |

Each missing header produces a `PluginFinding` with the header name, recommended value, and the evidence (raw response headers) attached.

### TLS / Certificate Check (`ssl_check`)

Applies to: port 443, port 8443, or any service with `service_guess = "https"`.

Makes two SSL connections (one permissive, one strict) and checks:

| Check | Severity |
|---|---|
| Weak TLS version (SSLv2, SSLv3, TLSv1, TLSv1.1 accepted) | MEDIUM |
| Certificate expired | CRITICAL |
| Certificate expiring within 30 days | HIGH |
| Self-signed certificate | LOW |

### Writing a custom plugin

Place a Python file in `vuln-scanner/scanner/plugins/`. It is discovered automatically at runtime — no registration step required.

```python
from __future__ import annotations
from typing import TYPE_CHECKING
from scanner.plugins.base import BasePlugin, PluginFinding

if TYPE_CHECKING:
    from scanner.core.models import ServiceInfo


class MyPlugin(BasePlugin):
    name = "my_plugin"
    description = "Checks something interesting."

    def applies_to(self, service: "ServiceInfo") -> bool:
        return service.port == 8080 and service.state == "open"

    def run(self, service: "ServiceInfo", host: str) -> list[PluginFinding]:
        # do your check here
        return [
            PluginFinding(
                plugin_name=self.name,
                title="Something found",
                description="Details of what was found.",
                severity="HIGH",
                evidence="raw evidence string",
            )
        ]
```

**Plugin contract:**

- `name` and `description` must be class-level string attributes.
- `applies_to` is called for every open service; return `True` to opt in.
- `run` is called only when `applies_to` returned `True`. It must not raise — exceptions are caught by the CLI runner and logged as warnings.
- `severity` must be one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- `evidence` is optional but recommended — include raw response data to support findings.

---

## Scan History and Diff

Every completed scan is automatically saved to the `scan_history` table in `~/.vuln-scanner/cve.db`. Scans are identified by target and timestamp.

You can label a scan when loading it for a diff using `--label-a` / `--label-b`:

```bash
# Save a baseline scan
vuln-scanner scan --target 10.0.0.0/24 --ports 1-1024 --output-json baseline.json

# Run a follow-up scan later
vuln-scanner scan --target 10.0.0.0/24 --ports 1-1024 --output-json followup.json

# See what changed
vuln-scanner diff baseline.json followup.json --output-html changes.html
```

**DiffReport fields:**

| Field | Description |
|---|---|
| `scan_a_date` / `scan_b_date` | Timestamps of the two scans |
| `new_ports` | Ports open in scan B but not scan A |
| `closed_ports` | Ports open in scan A but not scan B |
| `new_cves` | CVEs present in scan B but not scan A |
| `resolved_cves` | CVEs present in scan A but not scan B |
| `new_critical` | Count of new CRITICAL-severity CVEs |
| `new_high` | Count of new HIGH-severity CVEs |

---

## Running with Docker

Raw SYN scanning requires `CAP_NET_RAW`. The provided Docker image handles this automatically.

```bash
# Build the image
docker compose build

# Sync the CVE database (writes to a named volume)
docker compose run scanner vuln-scanner sync-db

# Scan a target
docker compose run scanner vuln-scanner scan \
  --target 192.168.1.1 \
  --ports 22,80,443 \
  --output-json /data/results.json

# Generate a report
docker compose run scanner vuln-scanner report \
  /data/results.json \
  --output-html /data/report.html
```

The Docker container grants `CAP_NET_RAW` automatically, so SYN probes work without `sudo` inside the container. OS fingerprinting (TTL + TCP window) is only available when SYN probes succeed.

---

## Ethical Use

Only scan systems you own or have explicit written permission to test. Unauthorised port scanning may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and equivalent laws in other jurisdictions.

This tool is intended for:
- Security assessments of your own infrastructure
- Authorised penetration testing engagements
- Lab and CTF environments
- Defensive security research

Running this tool against systems without authorisation is illegal and unethical.

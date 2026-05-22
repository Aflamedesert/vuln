# vuln-scanner

A network vulnerability scanner written in Python — raw TCP SYN probes via Scapy, async banner grabbing, offline CVE enrichment from the full NVD dataset, EPSS exploit scoring, a drop-in plugin system, and JSON/HTML/PDF reporting. No nmap. No subprocess wrappers.

![Demo placeholder — replace with asciinema export](docs/demo.gif)

---

## What makes this non-trivial

Most "scanners" shell out to nmap and parse its XML output. This one doesn't.

- **Raw SYN probes** — Scapy sends crafted TCP SYN packets and reads the response flags directly, giving access to TTL and window size for OS fingerprinting. Falls back to `socket.connect_ex` automatically when `CAP_NET_RAW` is unavailable.
- **Offline CVE database** — The NVD 2.0 REST API has a 5 req/30 s rate limit and thousands of pages per year. Instead of hitting it live, `sync-db` caches the entire dataset in a local SQLite file (~500 k CVEs) with indexed CPE lookups that resolve in under 1 ms.
- **CPE banner matching** — Mapping a free-text banner like `"Apache/2.4.52 (Ubuntu)"` to a NVD CPE URI requires a three-stage pipeline: banner normalisation → vendor/product/version extraction → exact / alias / prefix DB lookup, each with a confidence score.
- **EPSS prioritisation** — CVSS measures how bad a vulnerability *could* be; EPSS measures how likely it is to be exploited *this month*. Both scores appear side by side so triage decisions can be evidence-based.
- **Plugin architecture** — Drop a file into `scanner/plugins/` and it is discovered automatically at runtime via `pkgutil`; no registration step. Two plugins ship built-in: HTTP security-header checks and TLS/certificate inspection.

---

## Features

| | |
|---|---|
| Scapy SYN scan + TCP-connect fallback | OS fingerprint (TTL + TCP window) |
| Async banner grabbing — SSH, HTTP/S, FTP, SMTP, MySQL | Version string extraction per protocol |
| NVD 2.0 offline sync — CVSS v3/v2, CPE range matching | EPSS daily exploit-probability scores |
| Drop-in plugin system | HTTP security-header plugin |
| TLS version + cert expiry + self-signed plugin | Scan diff (ports, CVEs, labels) |
| Rich CLI tables | JSON, self-contained HTML, PDF reports |
| SQLite scan history | ≥ 80% test coverage, strict mypy, ruff |

---

## Quick Start

```bash
# Recommended: run in Docker (handles CAP_NET_RAW automatically)
docker compose build
docker compose run scanner vuln-scanner scan --target 192.168.1.0/24 --ports 22,80,443

# Or install locally (needs libpcap-dev + tcpdump on Linux)
pip install -e ".[dev]"
vuln-scanner scan --target 127.0.0.1 --ports 8000-8080   # TCP-connect, no root needed
```

---

## How it works

```
vuln-scanner scan
 ├─ scan_host()          port_scanner.py   Scapy SYN → TCP-connect fallback, async semaphore
 ├─ grab_banner()        banner_grabber.py asyncio.open_connection, protocol-specific probes
 ├─ fingerprint_os()     os_fingerprint.py TTL + TCP window table lookup
 ├─ enrich_results()     cve_lookup.py     CPE match → version range filter → CVEMatch list
 │    ├─ match_banner()  cpe_matcher.py    normalise → extract → exact/alias/prefix lookup
 │    └─ get_epss_score() epss.py          SQLite lookup, most-recent score_date
 ├─ discover_plugins()   plugins/base.py   pkgutil discovery, BasePlugin ABC
 │    ├─ HttpHeadersPlugin               HEAD request, 4 header checks
 │    └─ SSLCheckPlugin                  2-connection TLS version + cert checks
 └─ build_report()       reporting/        ScanReport → JSON / Jinja2 HTML / WeasyPrint PDF
```

Data flows one way. Nothing outside `cli.py` has side effects; every layer is independently testable.

---

## Usage

### Scan

```bash
vuln-scanner scan --target 192.168.1.10 --ports 22,80,443,3306
vuln-scanner scan --target 10.0.0.0/24  --ports 1-1024 --concurrency 200 --timeout 1.5 \
    --output-json results.json --output-html report.html --output-pdf report.pdf
```

### Sync CVE + EPSS data

```bash
vuln-scanner sync-db                  # NVD last two years
vuln-scanner sync-db --epss           # also pull today's EPSS scores
vuln-scanner sync-db --year 2021 --year 2022
```

### Diff two scans

```bash
vuln-scanner diff before.json after.json
vuln-scanner diff --label-a baseline --label-b weekly --output-html delta.html
```

### Report from saved JSON

```bash
vuln-scanner report results.json --output-html report.html --output-pdf report.pdf
```

---

## EPSS Scores

[EPSS (Exploit Prediction Scoring System)](https://www.first.org/epss/) is a daily ML model
that estimates the probability a CVE will be exploited in the wild within 30 days.

**Why it matters:** a CVE with CVSS 9.8 and EPSS 0.003 is less immediately urgent than one
with CVSS 7.5 and EPSS 0.975. EPSS surfaces the 2–5% of CVEs worth patching first.

After `vuln-scanner sync-db --epss`, every CVE match shows an EPSS probability and percentile
in the CLI table (`0.975 (99th)`) and as a badge in the HTML report.

---

## Plugins

Plugins run after CVE enrichment. Findings surface in the CLI table, JSON (`plugin_findings`),
HTML, and PDF.

### Built-in plugins

| Plugin | Trigger | Findings |
|---|---|---|
| `http-headers` | `service_guess` is `http` or `https` | Missing XFO (MEDIUM), CSP (MEDIUM), XCTO (LOW), HSTS on HTTPS (HIGH) |
| `ssl-check` | Port 443/8443 or `service_guess == "https"` | Weak TLS <1.2 (MEDIUM), cert expiring ≤30 d (HIGH), expired (CRITICAL), self-signed (LOW) |

### Writing a plugin

Create `scanner/plugins/my_plugin.py` — it is discovered automatically:

```python
from scanner.core.models import ServiceInfo
from scanner.plugins.base import BasePlugin, PluginFinding

class MyPlugin(BasePlugin):
    name = "my-plugin"
    description = "Checks for a custom condition."

    def applies_to(self, service: ServiceInfo) -> bool:
        return service.port == 8080

    def run(self, service: ServiceInfo, host: str) -> list[PluginFinding]:
        return [
            PluginFinding(
                plugin_name=self.name,
                title="Issue title",
                description="Explanation.",
                severity="HIGH",       # CRITICAL | HIGH | MEDIUM | LOW
                evidence="detail",     # optional
            )
        ]
```

### Adding a CPE vendor alias

Banner says "Jetty" but NVD says "eclipse"? Add one line to `_ALIASES` in
`scanner/enrichment/cpe_matcher.py`:

```python
"jetty": "eclipse",
```

---

## Development

```bash
pip install -e ".[dev]"

# Tests (unit only — no network, no raw sockets)
pytest tests/unit/ -v

# Full suite + coverage (gate: ≥ 80%)
pytest tests/ --cov=scanner --cov-report=term-missing -v

# Lint + types
ruff check scanner/ && mypy scanner/
```

CI runs on every push: installs `libpcap-dev`, runs the full suite, enforces the coverage gate,
uploads to Codecov.

---

## Technical write-up

Design decisions, the CPE matching problem, known limitations, and what I would improve next:
[**docs/write-up.md**](docs/write-up.md).

---

## Ethical Use

For **authorised testing only** — hosts and networks you own or have explicit written permission
to test. Unauthorised port scanning may be illegal in your jurisdiction.

---

## License

MIT

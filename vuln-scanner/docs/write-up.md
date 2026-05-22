# vuln-scanner — Technical Write-Up

## Design Decisions

### Scapy instead of nmap

The obvious choice for a network scanner is to shell out to nmap, but that would make the project a thin wrapper around an external binary. Scapy lets us send raw SYN packets and inspect the response flags directly in Python, which means the scanner can report TTL and TCP window values (used for OS fingerprinting) that a subprocess call would throw away. The trade-off is a hard dependency on `CAP_NET_RAW` and `libpcap`, which is why the code falls back transparently to a plain `socket.connect_ex` probe whenever a `PermissionError` is raised — the fallback loses OS fingerprint data but never crashes.

### SQLite instead of a live API

The NVD 2.0 REST API enforces a 5-requests/30s rate limit (without an API key) and returns JSON payloads up to 2,000 CVEs per page, with thousands of pages per year. Hitting it live on every scan would be slow, fragile, and potentially rate-limited. Caching the entire dataset locally in SQLite (currently ~500k CVEs, ~2 GB uncompressed) means scans are fully offline after the initial sync. The sync itself splits each calendar year into 90-day windows (NVD's maximum range per request) and commits in 500-record batches to keep memory flat.

### Two-connection SSL check

The standard approach for checking TLS version *and* certificate validity in one connection is impossible: `ssl.CERT_NONE` is required to talk to servers with self-signed or expired certs (otherwise `wrap_socket` throws before you can read the TLS version), but `ssl.CERT_REQUIRED` is required to actually validate the certificate. The plugin therefore makes two lightweight connections: the first with `CERT_NONE` reads `ssock.version()`, and the second with `CERT_REQUIRED` either returns a cert dict (for expiry checking) or raises `ssl.SSLCertVerificationError` (for self-signed / expired classification). This is slightly more network traffic but it avoids reimplementing certificate parsing with the `cryptography` package.

### Plugin architecture using `pkgutil` discovery

Plugins are discovered at runtime by iterating `pkgutil.iter_modules` over the `scanner/plugins/` directory, importing each module, and collecting classes that are concrete subclasses of `BasePlugin`. This means adding a new plugin is a single file drop — no registration list, no config change — which is the pattern used by tools like pytest (its plugin system works the same way). The downside is that import-time errors in one plugin file silently skip that plugin; a production system would want explicit error reporting here.

### `dataclasses` throughout

Every data boundary in the pipeline (`ServiceInfo`, `ScanResult`, `CVEMatch`, `EnrichedService`, `PluginFinding`) is a `dataclass`. This gives free `__repr__`, structural equality in tests (`assert result == expected`), and `dataclasses.asdict()` for JSON serialisation — no hand-written `to_dict()` methods. The only subtlety is the circular-import risk between `core/models.py` and `plugins/base.py`: resolved by guarding the `PluginFinding` import under `TYPE_CHECKING` so it is never evaluated at runtime (possible because `from __future__ import annotations` makes all annotations lazy strings).

---

## Hardest Problem

### CPE matching

Common Platform Enumeration (CPE) identifiers look like `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*`. A CVE record in the NVD database is linked to a CPE URI, not to a free-text string like "Apache Log4j 2.14.1". But the only thing the scanner has from a live service is a banner string — whatever the server decided to put in its HTTP `Server:` header or SSH greeting.

The gap between a banner and a CPE URI is bridged by a three-stage pipeline:

1. **Normalisation** — lowercase, replace punctuation with spaces, collapse whitespace. "Apache/2.4.52 (Ubuntu)" becomes "apache 2 4 52 ubuntu".

2. **Component extraction** — three regex patterns are tried in order: `vendor/product/version` (e.g. `nginx/1.18.0`), `product version` (e.g. `OpenSSH 8.2`), and a fallback that captures anything that looks like `word digits`. This step produces a `(vendor, product, version)` triple.

3. **Match pipeline** — the triple is tried against the database in order of confidence: (a) exact CPE URI lookup (conf=0.95), (b) alias substitution for known vendor name variations like "openssh→ssh" (conf=0.80), (c) a prefix LIKE search against the CPE URI column (conf=0.80). A miss yields conf=0.0.

What makes this genuinely hard:

- **Vendor name chaos**: the NVD uses "apache" but a banner might say "Apache", "ASF", or nothing at all. The alias table helps but can never be exhaustive.
- **Version range predicates**: CPE entries carry `versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding` fields. Evaluating them requires a semantic version comparison that works even when version strings are non-semver (e.g. "2.4.52-ubuntu3.8"). The implementation uses tuple comparison on the dot-split parts, which handles most cases but breaks on pre-release suffixes.
- **False positives**: a prefix search for "nginx" will match every CVE that affects any nginx product, including versions the scanned service may not run. Without a reliable version string the scanner errs on the side of reporting too much rather than too little.

An ML-based approach (embedding banner strings, training a classifier against known CPE URIs) would likely raise true positive rates substantially, but would require a labelled training corpus that doesn't exist publicly.

---

## What I Would Improve

**UDP scanning** — the current scanner is TCP-only. Many critical services (DNS on 53, SNMP on 161/162, NTP on 123) run over UDP. Scapy supports UDP probes but the response logic is completely different (no SYN-ACK handshake; you fire a probe and either get a response, an ICMP port-unreachable, or silence). This was intentionally deferred because UDP scanning is much slower and noisier, but it's the most significant capability gap.

**ML-based CPE matching** — the regex extraction pipeline described above is brittle. A sentence-transformer model fine-tuned on `(banner_string, cpe_uri)` pairs would be far more robust, especially for obscure or rebranded products. The main obstacle is training data: we would need a large corpus of confirmed `(banner, CVE)` pairs, which doesn't exist in public form.

**Parallel plugin execution** — plugins run serially per service. Each SSL check makes two TCP connections, and each HTTP-headers check makes one. On a target with many open HTTPS ports this serialises all the TLS handshakes. Converting the plugin runner to `asyncio.gather` with a semaphore would cut scan time significantly for wide-open targets.

**Smarter CPE version range handling** — the current `version_in_range` uses split-and-compare, which mishandles pre-release strings (`1.0.0-rc1 < 1.0.0` is true in semver but the implementation considers them equal). Switching to the `packaging` library's `Version` type would fix this for PEP 440 versions and substantially improve it for others.

**Structured plugin output in JSON/diff** — plugin findings are serialised to JSON via `dataclasses.asdict()` but are not surfaced in the diff engine. A scan diff currently reports new/closed ports and new/resolved CVEs, but not "this port gained a self-signed certificate finding between scan A and scan B". Adding plugin findings to the diff model would make the change tracking much more actionable.

---

## What I Learned

**`asyncio` and threads are uneasy partners** — Scapy's packet capture requires blocking I/O that cannot run inside an event loop, so `_syn_probe` runs in a `ThreadPoolExecutor` driven by an async wrapper that applies a `Semaphore` for backpressure. Getting the teardown right (draining all futures before closing the loop) took more iteration than expected. The key insight is that `loop.run_in_executor` returns a coroutine, so `asyncio.gather` can wait for all of them uniformly even though the underlying work is thread-based.

**SQLite is surprisingly capable for read-heavy workloads** — WAL mode (`PRAGMA journal_mode=WAL`) allows concurrent readers while a single writer is active. With `CREATE INDEX ON cpe_matches(cpe_uri)`, the CPE lookup for a single service takes under 1 ms even against a 500k-record database. The `INSERT OR REPLACE` upsert pattern (which is syntactic sugar for delete + insert) means the sync can be re-run safely without duplicate data. For a project at this scale SQLite was the right tool — a PostgreSQL setup would have added operational complexity with no performance benefit.

**`ssl.SSLContext` exposes more than I expected** — I assumed checking a TLS certificate would require the `cryptography` package, but Python's standard `ssl` module can retrieve the peer certificate as a plain dict (via `ssock.getpeercert()`), including the `notAfter` field needed for expiry checks. The tricky part is that `getpeercert()` returns `None` when the context uses `CERT_NONE`, and the mypy stubs reflect this with a complex union return type — which is how I learned that stub files can be more precise about runtime behaviour than the official documentation.

**Jinja2 autoescaping is opt-in for non-HTML extensions** — the template is named `report.html.j2`. Jinja2's `select_autoescape` escapes variables in templates whose name ends in `.html` or `.xml`, but it does not recognise `.j2` as an HTML template by default. The fix is to pass `["html", "j2"]` to `select_autoescape`, which tells Jinja2 that any template ending in `.j2` should also be HTML-escaped. Without this, a banner string containing `<script>` would be rendered verbatim into the HTML report.

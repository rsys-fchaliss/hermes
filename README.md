# Hermes

Extract closed CVEs from container build logs and produce a structured CSV report.

Hermes parses Docker BuildKit build logs, identifies installed/upgraded packages, detects the Linux distribution, and queries security databases to find CVEs that have been fixed in the installed package versions.

## Supported Distributions

| Distro | Source | Speed |
|--------|--------|-------|
| Alpine | [Alpine secdb](https://secdb.alpinelinux.org/) | ~2s per container |
| Rocky / RHEL | [Red Hat Security Data API](https://access.redhat.com/hydra/rest/securitydata) | ~20-40s per source package |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    closed-cv-info-from-buildlogs.py              │
│                         (CLI Entry Point)                        │
└────────────────────────────────┬────────────────────────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
          ▼                      ▼                      ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  hermes/config   │  │ hermes/parsers/  │  │hermes/csv_writer │
│                  │  │                  │  │                  │
│ • YAML config    │  │ • distro_detector│  │ • CSV generation │
│ • CLI args       │  │ • rpm_log_parser │  │ • Report output  │
│ • Validation     │  │ • apk_log_parser │  │                  │
└──────────────────┘  └────────┬─────────┘  └──────────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ hermes/cve_sources/  │
                    │                      │
                    │ • redhat_api.py      │
                    │ • alpine_secdb.py    │
                    │ • osv_api.py         │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │hermes/version_compare│
                    │                      │
                    │ • RPM epoch:ver-rel  │
                    │ • Alpine ver-rN      │
                    └──────────────────────┘
```

### Pipeline Flow

1. **Extract** — Unpack the input archive (`.tar.gz` or `.zip`) containing build logs
2. **Parse** — Detect distro (Alpine/Rocky) and parse installed packages from each log
3. **Query** — Look up closed CVEs per package from the appropriate security database
4. **Enrich** _(optional)_ — Add severity, dates via OSV.dev
5. **Report** — Write CSV with all closed CVEs

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pyyaml requests
```

Or on systems without venv restrictions:

```bash
pip install pyyaml requests
```

## Usage

### CLI

```bash
python3 closed-cv-info-from-buildlogs.py \
  --product "MyProduct" \
  --version "1.0.0" \
  --input build-logs.tar.gz \
  --output closed-cves.csv
```

### YAML Configuration (preferred)

Create a `hermes.yaml` file:

```yaml
product: "Radisys_MRF"
project_version: "20.0.2.0"
input: "container-log.tar.gz"
output: "closed-cves.csv"
rate_limit: 0.5
# distro_filter: alpine    # optional: only process alpine or rocky
# skip_enrichment: true    # optional: skip OSV.dev metadata lookup
```

Then run:

```bash
python3 closed-cv-info-from-buildlogs.py --config hermes.yaml
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--product` | Product name for the report |
| `--version` | Project version for the report |
| `--input` | Path to `.tar.gz` or `.zip` containing build logs |
| `--output` | Output CSV path (default: `closed-cves.csv`) |
| `--config` | YAML config file path (default: `hermes.yaml`) |
| `--rate-limit` | Seconds between API calls (default: `0.5`) |
| `--distro-filter` | Only process `rocky` or `alpine` containers |
| `--skip-enrichment` | Skip OSV.dev metadata enrichment |

## Output Format

The CSV report contains:

| Column | Description |
|--------|-------------|
| Product | Product name |
| Project Version | Release version |
| Container Name | Name extracted from the build log |
| Component Name | Package name and version (e.g. `curl-7.61.1-34.el8_10.11`) |
| Closed CVE | CVE identifier (e.g. `CVE-2023-46218`) |
| Source | Where the fix info came from (`distro` or `upstream`) |
| Backported | Whether the fix is backported (`yes`/`no`) |
| Severity | CVE severity level |
| Published Date | When the CVE was published |
| Modified Date | Last modification date |

## Build Log Format

Hermes expects Docker BuildKit log output. Supported formats within logs:

**RPM-based (Rocky/RHEL):**

```
#6 162.0   curl-7.61.1-34.el8_10.11.x86_64
#6 162.1   openssl-libs-1:1.1.1k-15.el8_10.x86_64
```

**Alpine (apk):**

```
#5 2.105 (1/48) Installing musl (1.2.5-r0)
#5 2.200 (2/48) Upgrading busybox (1.36.1-r28 -> 1.36.1-r31)
```

## Project Structure

```
hermes/
├── closed-cv-info-from-buildlogs.py   # CLI entry point
├── hermes.yaml                         # Configuration (create this)
├── hermes/
│   ├── models.py                      # Component, ClosedCVE dataclasses
│   ├── config.py                      # Config loading & validation
│   ├── version_compare.py            # RPM & Alpine version comparison
│   ├── csv_writer.py                  # CSV report generation
│   ├── parsers/
│   │   ├── distro_detector.py        # Auto-detect Alpine/Rocky from log
│   │   ├── rpm_log_parser.py         # Parse yum/dnf package installs
│   │   └── apk_log_parser.py         # Parse apk package installs
│   └── cve_sources/
│       ├── redhat_api.py             # Red Hat Security Data API
│       ├── alpine_secdb.py           # Alpine security database
│       └── osv_api.py                # OSV.dev enrichment
└── container-log.tar.gz               # Sample input (build logs)
```

## Performance Notes

- **Alpine** queries are fast (~2s per container) since secdb JSON is cached per branch
- **Red Hat** queries are slow due to per-CVE detail fetches required by the API
  - Binary packages are deduplicated by source package name before querying
  - Detail fetches are capped at 50 per package
  - Use `--distro-filter alpine` for quick Alpine-only runs
  - Consider using `--rate-limit 0.2` to speed up at the cost of higher API load

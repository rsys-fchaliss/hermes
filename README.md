# Hermes

Extract closed CVEs from container build logs and produce a structured CSV report.

Hermes parses Docker BuildKit build logs, identifies installed/upgraded packages, detects the Linux distribution, and queries security databases to find CVEs that have been **newly closed** by the specific package upgrades in that build.

## Key Capabilities

- **Automatic distro detection** — identifies Alpine or Rocky/RHEL from build log content
- **Precise CVE filtering** — only reports CVEs fixed between the previous and current package version (not all historical CVEs)
- **Cross-container deduplication** — same package+version across multiple containers is queried once and reported in a single row
- **Sub-package merging** — CVEs shared by binary sub-packages (e.g. `libcrypto3` + `libssl3`) are deduplicated into one entry
- **Errata fix dates** — fetches actual fix release dates from Red Hat detail API (not misleading OSV.dev database timestamps)
- **Split reports** — CVEs in main CSV, fresh installs and no-baseline packages in a separate `_packages.csv` for easy tracking
- **Manual check warnings** — upgraded packages without baseline version data are flagged for manual review
- **OSV.dev enrichment** — severity and published dates filled from OSV when not available from distro sources

## CVE Filtering Logic

| Package Category | How Detected | CVE Filter |
|------------------|--------------|------------|
| Upgraded (with baseline) | `Upgraded:` block + `Cleanup:` lines | Range: `previous_version < fix_version <= current_version` |
| Upgraded (no baseline) | `Upgraded:` block, no `Cleanup:` lines | Skipped — listed as `MANUAL CHECK REQUIRED` |
| Fresh install (Alpine) | `Installing` lines | Exact match: `fix_version == installed_version` |
| Fresh install (Rocky) | `Installed:` block | Listed in `_packages.csv` (API cost, near-zero hit rate) |

> **Note**: CVE publication year is NOT a filter criteria. A CVE-2023 or CVE-2024 appearing in a 2026 report is expected — it means the previous container version was vulnerable to that CVE, and this upgrade fixed it.

## Supported Distributions

| Distro | Source | Speed |
|--------|--------|-------|
| Alpine | [Alpine secdb](https://secdb.alpinelinux.org/) | ~2s per container |
| Rocky / RHEL | [Red Hat Security Data API](https://access.redhat.com/hydra/rest/securitydata) | ~5-15s per source package |

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
│ • CLI args       │  │ • rpm_log_parser │  │ • Deduplication  │
│ • Validation     │  │ • apk_log_parser │  │ • Grouping       │
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
2. **Parse** — Detect distro (Alpine/Rocky), parse packages, capture previous versions from `Cleanup:` / `Upgrading` lines
3. **Classify** — Categorize packages: upgraded-with-baseline, upgraded-no-baseline, or fresh install
4. **Query** — Look up closed CVEs per package from the appropriate security database (with cross-container cache)
5. **Errata dates** — Fetch actual fix release dates from Red Hat detail API for matched CVEs
6. **Enrich** _(optional)_ — Add severity, published dates via OSV.dev
7. **Deduplicate** — Merge same CVE across containers and sub-packages into single rows
8. **Report** — Write main CVE CSV + separate package info CSV for fresh installs/no-baseline

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
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

## Running as a CI/CD Job

### GitLab CI

```yaml
closed-cve-report:
  stage: security
  image: python:3.12-slim
  script:
    - pip install pyyaml requests
    - python3 closed-cv-info-from-buildlogs.py --config hermes.yaml
  artifacts:
    paths:
      - closed-cves.csv
      - closed-cves_packages.csv
    expire_in: 90 days
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

### GitHub Actions

```yaml
jobs:
  closed-cve-report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install pyyaml requests
      - run: python3 closed-cv-info-from-buildlogs.py --config hermes.yaml
      - uses: actions/upload-artifact@v4
        with:
          name: closed-cve-report
          path: |
            closed-cves.csv
            closed-cves_packages.csv
```

### Jenkins Pipeline

```groovy
pipeline {
    agent { docker { image 'python:3.12-slim' } }
    stages {
        stage('CVE Report') {
            steps {
                sh 'pip install pyyaml requests'
                sh 'python3 closed-cv-info-from-buildlogs.py --config hermes.yaml'
                archiveArtifacts artifacts: 'closed-cves*.csv'
            }
        }
    }
}
```

### Docker (standalone)

```bash
docker run --rm -v $(pwd):/work -w /work python:3.12-slim \
  sh -c "pip install pyyaml requests && python3 closed-cv-info-from-buildlogs.py --config hermes.yaml"
```

### CI/CD Integration Tips

- **Input**: store the build log archive as a CI artifact from the container build stage, then pass it to the CVE report stage
- **Trigger**: run after every container image build, or on a schedule against the latest build logs
- **Rate limiting**: use `rate_limit: 0.3` for CI (faster, fewer concurrent jobs) or `rate_limit: 1.0` for shared runners
- **Speed**: use `--distro-filter alpine` for fast feedback (~10s), full run with Rocky takes ~2-5 min depending on number of upgraded packages
- **Enrichment**: use `--skip-enrichment` in CI for speed if severity data from distro sources is sufficient

## Output Format

Two CSV files are produced:

### Main Report (`closed-cves.csv`)

Contains only actual closed CVEs:

| Column | Description |
|--------|-------------|
| Product | Product name |
| Project Version | Release version |
| Container Name | Comma-separated list of containers sharing this CVE |
| Component Name | Package name(s) and version (sub-packages merged) |
| Closed CVE | CVE identifier |
| Source | `distro` or `upstream` |
| Backported | Whether the fix is backported (`yes`/`no`) |
| Severity | CVE severity: critical, high, medium, low |
| Published Date | When the CVE was published |
| Fix Date | When the distro shipped the fix (errata release date) |

### Package Info Report (`closed-cves_packages.csv`)

Contains fresh installs and no-baseline packages for tracking:

| Column | Description |
|--------|-------------|
| Product | Product name |
| Project Version | Release version |
| Container Name | Comma-separated list of containers |
| Component Name | Package name and version |
| Status | `FRESH INSTALL` or `UPGRADED (NO BASELINE)` |

### Example Output

```csv
Product,Project Version,Container Name,Component Name,Closed CVE,Source,Backported,Severity,Published Date,Fix Date
Radisys_MRF,20.0.2.0,"annlab, mrfp, oamp",curl-7.61.1-34.el8_10.11,CVE-2024-5535,distro,yes,low,2024-06-27,2024-07-15
Radisys_MRF,20.0.2.0,sidecar,"libcrypto3-3.3.7-r0, libssl3-3.3.7-r0",CVE-2024-12797,distro,yes,medium,2025-02-11,
```

## Build Log Format

Hermes expects Docker BuildKit log output. Supported formats within logs:

**RPM-based (Rocky/RHEL) — Upgrade with Cleanup (best: captures old version):**

```
#6 160.0   Cleanup          : curl-7.61.1-30.el8_10.2.x86_64           2/4
#6 162.0 Upgraded:
#6 162.1   curl-7.61.1-34.el8_10.11.x86_64
```

**RPM-based — Installed (fresh, no previous version):**

```
#6 163.0 Installed:
#6 163.1   tar-2:1.30-6.el8_7.1.x86_64
```

**Alpine (apk) — Upgrade (captures old → new):**

```
#5 2.200 (2/48) Upgrading busybox (1.36.1-r28 -> 1.36.1-r31)
```

**Alpine (apk) — Install:**

```
#5 2.105 (1/48) Installing musl (1.2.5-r0)
```

> **Tip**: For best results with Rocky/RHEL containers, ensure `yum update` or `dnf upgrade` produces verbose transaction output (Cleanup lines). Without these, upgraded packages are flagged as `MANUAL CHECK REQUIRED`.

## Project Structure

```
hermes/
├── closed-cv-info-from-buildlogs.py   # CLI entry point
├── hermes.yaml                         # Configuration (create this)
├── requirements.txt                    # Python dependencies
├── .gitignore
├── hermes/
│   ├── models.py                      # Component, ClosedCVE dataclasses
│   ├── config.py                      # Config loading & validation
│   ├── version_compare.py            # RPM & Alpine version comparison
│   ├── csv_writer.py                  # CSV report + deduplication
│   ├── parsers/
│   │   ├── distro_detector.py        # Auto-detect Alpine/Rocky from log
│   │   ├── rpm_log_parser.py         # Parse yum/dnf installs + Cleanup lines
│   │   └── apk_log_parser.py         # Parse apk install/upgrade
│   └── cve_sources/
│       ├── redhat_api.py             # Red Hat Security Data API (list-only, no detail fetches)
│       ├── alpine_secdb.py           # Alpine security database (cached)
│       └── osv_api.py                # OSV.dev severity enrichment
└── container-log.tar.gz               # Sample input (build logs)
```

## Performance

| Scenario | Time | Notes |
|----------|------|-------|
| Alpine-only (5 containers) | ~10s | secdb cached after first download |
| Rocky (88 upgraded packages) | ~2-5 min | Depends on rate_limit and cache hits |
| Repeat containers (same OS) | ~0s | Cross-container cache eliminates re-queries |

- **Minimal detail fetches** — version matching uses `affected_packages` from list endpoint; detail API only fetched for matched CVEs (cached) to get errata dates
- **Product filter** — API query narrowed to target RHEL version (e.g., RHEL 8 only)
- **Source package deduplication** — `openssl-libs`, `openssl-devel` queried once as `openssl`
- **Cross-container cache** — if `oamp` queries `curl`, `annlab` and `mrfp` reuse the result instantly
- **CVE detail cache** — detail API responses cached across packages to avoid redundant fetches

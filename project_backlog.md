# Project Backlog

## Future Release Items

### SBOM-based Input

- Accept SPDX/CycloneDX SBOM as input instead of (or alongside) build logs
- Extract component names and versions directly from structured SBOM data
- Skip log parsing when SBOM is provided — feed directly into CVE lookup

### Previous Release Comparison

- Compare current release against a previous release to show only newly-closed CVEs
- Input: two ZIP files (previous + current) or a saved baseline file
- Output: delta CSV showing what changed between releases

### Open/Unfixed CVE Reporting

- Integrate with OSV.dev to report CVEs that are still open for the current versions
- Output a separate CSV or add an "Open CVEs" section to the report
- Priority scoring to highlight critical unfixed vulnerabilities

### Debian/Ubuntu Distro Support

- Add parser for apt-get build logs
- Integrate with Ubuntu Security Tracker and Debian Security Tracker APIs

### CI/CD Pipeline Integration

- GitHub Actions / GitLab CI integration
- Automatic report generation on container image build
- Fail pipeline if critical open CVEs exceed threshold

### Real-time / Scheduled Scanning

- Watch mode: re-scan when new build logs appear
- Scheduled runs with email/Slack notifications for new findings

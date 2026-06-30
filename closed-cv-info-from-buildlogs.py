#!/usr/bin/env python3
"""
Hermes — Extract closed CVEs from container build logs.

Usage:
    python closed-cv-info-from-buildlogs.py --product MyApp --version 2.5.0 --input build-logs.zip
    python closed-cv-info-from-buildlogs.py --config hermes.yaml
"""
import os
import sys
import zipfile
import tarfile
import tempfile
import logging

from hermes.config import parse_cli_args, build_config, validate_config
from hermes.parsers import parse_build_log
from hermes.cve_sources.redhat_api import get_closed_cves_redhat, _get_source_package_name
from hermes.cve_sources.alpine_secdb import get_closed_cves_alpine
from hermes.cve_sources.osv_api import enrich_cves
from hermes.csv_writer import write_csv, write_report

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


def extract_input(input_path: str, tmp_dir: str) -> list:
    """Extract ZIP or tar.gz input file to tmp_dir, return list of log file paths."""
    log_files = []

    if zipfile.is_zipfile(input_path):
        with zipfile.ZipFile(input_path, "r") as zf:
            zf.extractall(tmp_dir)
    elif tarfile.is_tarfile(input_path):
        with tarfile.open(input_path, "r:*") as tf:
            tf.extractall(tmp_dir)
    else:
        logger.error(f"Input file is not a valid ZIP or tar.gz: {input_path}")
        sys.exit(1)

    # Collect all files (non-directories) from extracted content
    for root, dirs, files in os.walk(tmp_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            # Skip very small files and hidden files
            if os.path.getsize(fpath) > 100 and not fname.startswith("."):
                log_files.append(fpath)

    return log_files


def process_container(log_path: str, config: dict, cve_cache: dict) -> list:
    """Process a single container build log and return CSV rows.
    
    cve_cache: shared dict keyed by (distro, src_name, version, release, epoch, prev_version, prev_release, prev_epoch)
               storing list of ClosedCVE objects. Avoids re-querying the same package across containers.
    """
    with open(log_path, "r", errors="replace") as f:
        log_content = f.read()

    distro, distro_version, container_name, components = parse_build_log(
        log_content, log_path
    )

    if not components:
        logger.info(f"  {container_name}: no packages found, skipping")
        return []

    # Apply distro filter if set
    distro_filter = config.get("distro_filter")
    if distro_filter and distro != distro_filter:
        logger.info(f"  {container_name}: skipping ({distro} != filter {distro_filter})")
        return []

    logger.info(f"  {container_name}: {len(components)} packages ({distro} {distro_version})")

    # Classify packages into 3 categories:
    # 1. Upgraded with known old version → range match (previous < fix <= current)
    # 2. Upgraded but old version unknown (no Cleanup lines) → skip (can't determine range)
    # 3. Freshly installed → exact-match only (fix == current)
    upgraded_with_baseline = [c for c in components if c.previous_version]
    upgraded_no_baseline = [c for c in components if c.was_upgraded and not c.previous_version]
    fresh = [c for c in components if not c.was_upgraded and not c.previous_version]

    if upgraded_no_baseline:
        logger.info(f"  {len(upgraded_with_baseline)} upgraded (with baseline), "
                    f"{len(upgraded_no_baseline)} upgraded (no baseline, skipping), "
                    f"{len(fresh)} freshly installed")
    elif fresh:
        logger.info(f"  {len(upgraded_with_baseline)} upgraded, {len(fresh)} freshly installed")

    # Only process packages where we can determine closed CVEs:
    # - upgraded_with_baseline: query with range filter (always)
    # - fresh installs: Alpine only (secdb is fast local lookup);
    #   skip for Rocky/Red Hat (API is expensive, exact-match almost never hits)
    # - upgraded_no_baseline: listed as warnings for manual check

    # Get closed CVEs from distro-native source (with cross-container cache)
    all_cves = []
    cache_hits = 0
    if distro == "rocky":
        # For Red Hat, only query upgraded packages with known baseline
        # Fresh installs are skipped: the API is rate-limited and exact-match
        # against Red Hat advisories almost never returns results
        source_groups = {}
        for comp in upgraded_with_baseline:
            src_name = _get_source_package_name(comp.name)
            if src_name not in source_groups:
                source_groups[src_name] = comp
        logger.info(f"  Querying {len(source_groups)} unique source packages "
                    f"(from {len(upgraded_with_baseline)} upgraded, skipping {len(fresh)} fresh installs)")
        for src_name, comp in source_groups.items():
            cache_key = (distro, src_name, comp.version, comp.release, comp.epoch,
                         comp.previous_version, comp.previous_release, comp.previous_epoch)
            if cache_key in cve_cache:
                all_cves.extend(cve_cache[cache_key])
                cache_hits += 1
            else:
                cves = get_closed_cves_redhat(comp, rate_limit=config["rate_limit"])
                cve_cache[cache_key] = cves
                all_cves.extend(cves)
    elif distro == "alpine":
        # For Alpine, query both upgraded and fresh (secdb is a fast cached JSON lookup)
        processable = upgraded_with_baseline + fresh
        for comp in processable:
            cache_key = (distro, comp.name, comp.version, "", "",
                         comp.previous_version, "", "")
            if cache_key in cve_cache:
                all_cves.extend(cve_cache[cache_key])
                cache_hits += 1
            else:
                cves = get_closed_cves_alpine(comp)
                cve_cache[cache_key] = cves
                all_cves.extend(cves)
    else:
        logger.warning(f"  Unsupported distro: {distro}")

    if cache_hits:
        logger.info(f"  Cache: {cache_hits} packages reused from previous containers")

    # Enrich with OSV.dev metadata
    if all_cves and not config.get("skip_enrichment"):
        enrich_cves(all_cves)

    # Convert to CSV rows
    rows = write_csv(
        all_cves,
        output_path="",
        product=config["product"],
        project_version=config.get("project_version", ""),
        container_name=container_name,
    )

    # Add warning rows for upgraded packages with no baseline (manual check needed)
    for comp in upgraded_no_baseline:
        rows.append({
            "Product": config["product"],
            "Project Version": config.get("project_version", ""),
            "Container Name": container_name,
            "Component Name": comp.display_name,
            "Closed CVE": "MANUAL CHECK REQUIRED",
            "Source": "no-baseline",
            "Backported": "",
            "Severity": "",
            "Published Date": "",
            "Fix Date": "",
        })

    # Add informational rows for freshly installed packages
    # For Rocky, fresh installs are not queried (API cost); list them for visibility
    # For Alpine, fresh installs ARE queried above, so only list unmatched ones
    fresh_to_list = fresh if distro == "rocky" else []
    for comp in fresh_to_list:
        rows.append({
            "Product": config["product"],
            "Project Version": config.get("project_version", ""),
            "Container Name": container_name,
            "Component Name": comp.display_name,
            "Closed CVE": "FRESH INSTALL",
            "Source": "fresh-install",
            "Backported": "",
            "Severity": "",
            "Published Date": "",
            "Fix Date": "",
        })

    return rows


def main():
    cli_args = parse_cli_args()
    config = build_config(cli_args)

    # Validate
    errors = validate_config(config)
    if errors:
        for err in errors:
            logger.error(err)
        sys.exit(1)

    input_path = config["input"]
    if not os.path.isfile(input_path):
        logger.error(f"Input file not found: {input_path}")
        sys.exit(1)

    logger.info(f"Product: {config['product']}")
    logger.info(f"Version: {config.get('project_version', '(not set)')}")
    logger.info(f"Input: {input_path}")
    logger.info(f"Output: {config['output']}")
    logger.info("")

    # Extract input archive
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_files = extract_input(input_path, tmp_dir)
        logger.info(f"Found {len(log_files)} log files")
        logger.info("")

        # Process each container log (shared cache across containers)
        all_rows = []
        cve_cache = {}  # Cross-container cache: same pkg+version = same CVEs
        for log_path in sorted(log_files):
            rows = process_container(log_path, config, cve_cache)
            all_rows.extend(rows)

        if cve_cache:
            logger.info(f"CVE cache: {len(cve_cache)} unique package queries cached")

    # Write final report
    cve_count, pkg_count = write_report(all_rows, config["output"])

    # Summary
    base, ext = os.path.splitext(config["output"])
    packages_path = f"{base}_packages{ext}"
    logger.info("")
    logger.info("=" * 60)
    logger.info(f"Total containers processed: {len(log_files)}")
    logger.info(f"Closed CVEs report: {cve_count} entries → {config['output']}")
    if pkg_count:
        logger.info(f"Package info report: {pkg_count} entries → {packages_path}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()

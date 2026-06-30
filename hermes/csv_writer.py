import csv
import logging
from typing import List
from hermes.models import ClosedCVE

logger = logging.getLogger(__name__)

CSV_COLUMNS = [
    "Product",
    "Project Version",
    "Container Name",
    "Component Name",
    "Closed CVE",
    "Source",
    "Backported",
    "Severity",
    "Published Date",
    "Fix Date",
]


PACKAGE_INFO_COLUMNS = [
    "Product",
    "Project Version",
    "Container Name",
    "Component Name",
    "Status",
]


def write_csv(
    closed_cves: List[ClosedCVE],
    output_path: str,
    product: str,
    project_version: str,
    container_name: str,
):
    """Write closed CVEs for a single container to a list of rows."""
    rows = []
    for cve in closed_cves:
        rows.append({
            "Product": product,
            "Project Version": project_version or "",
            "Container Name": container_name,
            "Component Name": cve.component.display_name,
            "Closed CVE": cve.cve_id,
            "Source": cve.source,
            "Backported": cve.backported,
            "Severity": cve.severity,
            "Published Date": cve.published_date,
            "Fix Date": cve.modified_date,
        })
    return rows


def _group_rows(all_rows: List[dict]) -> List[dict]:
    """
    Group rows by Closed CVE, merging container names and component names.

    Deduplication rules:
    1. Same CVE + same component across containers → merge container names
    2. Same CVE across sub-packages (e.g. libcrypto3 + libssl3) → merge component names

    This avoids double-counting when sub-packages from the same source report identical CVEs.
    """
    # Step 1: Group by (Product, Project Version, Closed CVE) to merge sub-packages
    grouped = {}
    for row in all_rows:
        key = (row["Product"], row["Project Version"], row["Closed CVE"])
        if key in grouped:
            existing = grouped[key]
            # Merge container names
            existing_containers = set(existing["Container Name"].split(", "))
            new_containers = set(row["Container Name"].split(", "))
            merged_containers = sorted(existing_containers | new_containers)
            existing["Container Name"] = ", ".join(merged_containers)
            # Merge component names (for sub-packages reporting same CVE)
            existing_components = set(existing["Component Name"].split(", "))
            if row["Component Name"] not in existing_components:
                existing_components.add(row["Component Name"])
                existing["Component Name"] = ", ".join(sorted(existing_components))
            # Keep the more informative severity/date
            if not existing["Severity"] and row["Severity"]:
                existing["Severity"] = row["Severity"]
            if not existing["Published Date"] and row["Published Date"]:
                existing["Published Date"] = row["Published Date"]
            if not existing["Fix Date"] and row["Fix Date"]:
                existing["Fix Date"] = row["Fix Date"]
        else:
            grouped[key] = dict(row)
    return list(grouped.values())


def write_report(all_rows: List[dict], output_path: str):
    """Write the CSV reports.
    
    - Main report (output_path): closed CVEs only
    - Package info report (*_packages.csv): fresh installs and no-baseline packages
    """
    import os

    # Separate actual CVE rows from informational entries
    info_sources = {"no-baseline", "fresh-install"}
    cve_rows = [r for r in all_rows if r["Source"] not in info_sources]
    warning_rows = [r for r in all_rows if r["Source"] == "no-baseline"]
    fresh_rows = [r for r in all_rows if r["Source"] == "fresh-install"]

    # --- Main CVE report ---
    grouped_cves = _group_rows(cve_rows)
    grouped_cves.sort(key=lambda r: (r["Component Name"], r["Closed CVE"], r["Container Name"]))

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(grouped_cves)

    logger.info(f"Wrote {len(grouped_cves)} CVE entries to {output_path}")

    # --- Package info report (fresh installs + no-baseline) ---
    grouped_warnings = _group_rows(warning_rows)
    grouped_fresh = _group_rows(fresh_rows)

    info_rows = []
    for row in grouped_warnings:
        info_rows.append({
            "Product": row["Product"],
            "Project Version": row["Project Version"],
            "Container Name": row["Container Name"],
            "Component Name": row["Component Name"],
            "Status": "UPGRADED (NO BASELINE)",
        })
    for row in grouped_fresh:
        info_rows.append({
            "Product": row["Product"],
            "Project Version": row["Project Version"],
            "Container Name": row["Container Name"],
            "Component Name": row["Component Name"],
            "Status": "FRESH INSTALL",
        })

    info_rows.sort(key=lambda r: (r["Status"], r["Component Name"], r["Container Name"]))

    if info_rows:
        base, ext = os.path.splitext(output_path)
        packages_path = f"{base}_packages{ext}"
        with open(packages_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=PACKAGE_INFO_COLUMNS)
            writer.writeheader()
            writer.writerows(info_rows)
        logger.info(f"Wrote {len(grouped_fresh)} fresh installs + "
                    f"{len(grouped_warnings)} no-baseline warnings to {packages_path}")

    return len(grouped_cves), len(info_rows)

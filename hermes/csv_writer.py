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
    "Modified Date",
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
            "Modified Date": cve.modified_date,
        })
    return rows


def _group_rows(all_rows: List[dict]) -> List[dict]:
    """
    Group rows that share the same Component Name + Closed CVE across containers.
    Merges container names into a comma-separated list in one row.
    This keeps the table clean when multiple containers from the same vendor/OS
    have identical packages and CVEs.
    """
    # Key: (Product, Project Version, Component Name, Closed CVE) -> merged row
    grouped = {}
    for row in all_rows:
        key = (row["Product"], row["Project Version"], row["Component Name"], row["Closed CVE"])
        if key in grouped:
            # Append container name if not already listed
            existing_containers = grouped[key]["Container Name"].split(", ")
            if row["Container Name"] not in existing_containers:
                existing_containers.append(row["Container Name"])
                grouped[key]["Container Name"] = ", ".join(sorted(existing_containers))
        else:
            grouped[key] = dict(row)
    return list(grouped.values())


def write_report(all_rows: List[dict], output_path: str):
    """Write the full CSV report. Groups identical CVEs across containers, sorted by Component, CVE.
    
    Packages with no baseline (upgraded but no old version known) are listed
    separately at the bottom as a 'manual check' section.
    """
    # Separate actual CVE rows from manual-check warnings
    cve_rows = [r for r in all_rows if r["Source"] != "no-baseline"]
    warning_rows = [r for r in all_rows if r["Source"] == "no-baseline"]

    # Group CVE rows with same component+CVE across containers
    grouped_cves = _group_rows(cve_rows)
    grouped_cves.sort(key=lambda r: (r["Component Name"], r["Closed CVE"], r["Container Name"]))

    # Group warning rows with same component across containers
    grouped_warnings = _group_rows(warning_rows)
    grouped_warnings.sort(key=lambda r: (r["Component Name"], r["Container Name"]))

    # Write: CVE entries first, then warnings at the bottom
    final_rows = grouped_cves + grouped_warnings

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(final_rows)

    logger.info(f"Wrote {len(grouped_cves)} CVE entries + {len(grouped_warnings)} manual-check warnings to {output_path}")

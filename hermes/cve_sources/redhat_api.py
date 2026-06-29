import re
import time
import logging
from typing import List
import requests

from hermes.models import Component, ClosedCVE
from hermes.version_compare import is_version_lte

logger = logging.getLogger(__name__)

BASE_URL = "https://access.redhat.com/hydra/rest/securitydata"

# Maximum pages to fetch from the list endpoint per package.
# Each page has up to 100 CVEs. 3 pages = 300 CVEs max per package.
MAX_PAGES = 3

# Maximum detail fetches per package to limit API calls.
# Detail fetch is needed for version comparison. With rate limiting,
# 50 fetches × 0.2s = 10s per package.
MAX_DETAIL_FETCHES = 50

# Common RPM sub-package suffixes to strip when querying the Red Hat API.
# The API only indexes source package names.
_RPM_SUFFIXES_TO_STRIP = [
    "-libs", "-devel", "-common", "-tools", "-utils",
    "-daemon", "-data", "-minimal", "-server", "-client",
    "-headless", "-static", "-doc", "-help",
    "-minimal-langpack", "-langpack", "-single",
    "-default-yama-scope", "-libelf", "-build-libs",
    "-softokn", "-softokn-freebl", "-sysinit", "-util",
    "-scripts", "-filesystem",
    "-wheel",  # python3-pip-wheel -> python3-pip
]

# Explicit source package mappings for cases where suffix stripping isn't enough
_RPM_SOURCE_MAP = {
    "platform-python": "python3",
    "platform-python-setuptools": "python3-setuptools",
    "python3-setuptools-wheel": "python3-setuptools",
    "python3-pip-wheel": "python3-pip",
    "python3-libs": "python3",
    "libcurl-minimal": "curl",
    "openssl-libs": "openssl",
    "glibc-common": "glibc",
    "glibc-minimal-langpack": "glibc",
    "libgcc": "gcc",
    "libstdc++": "gcc",
    "ca-certificates-bundle": "ca-certificates",
}


def _get_source_package_name(rpm_name: str) -> str:
    """Map an RPM binary package name to its likely source package name for API queries."""
    # Check explicit map first
    if rpm_name in _RPM_SOURCE_MAP:
        return _RPM_SOURCE_MAP[rpm_name]

    # Try stripping common suffixes
    for suffix in sorted(_RPM_SUFFIXES_TO_STRIP, key=len, reverse=True):
        if rpm_name.endswith(suffix):
            return rpm_name[: -len(suffix)]

    return rpm_name


def _extract_rpm_name_from_nevra(nevra: str) -> str:
    """Extract just the package name from a Red Hat NEVRA string like 'tar-2:1.30-6.el8_7.1'."""
    # Remove arch if present
    for arch in (".x86_64", ".noarch", ".i686", ".aarch64", ".src"):
        if nevra.endswith(arch):
            nevra = nevra[: -len(arch)]
            break
    # Right-split twice to get name
    parts = nevra.rsplit("-", 2)
    if len(parts) >= 3:
        return parts[0]
    elif len(parts) == 2:
        return parts[0]
    return nevra


def _package_name_matches(advisory_package: str, component_name: str) -> bool:
    """Check if a Red Hat advisory package field matches our component name."""
    extracted = _extract_rpm_name_from_nevra(advisory_package)
    return extracted == component_name


def _parse_fix_version(nevra: str) -> tuple:
    """Parse a Red Hat NEVRA into (epoch, version, release) for comparison.
    
    NEVRA format: name-[epoch:]version-release[.arch]
    The challenge is that package names can contain hyphens.
    Strategy: release never contains hyphens, version starts with a digit or epoch.
    So we rsplit on '-' and walk backwards to find the version-release boundary.
    """
    # Remove arch if present
    for arch in (".x86_64", ".noarch", ".i686", ".aarch64", ".src"):
        if nevra.endswith(arch):
            nevra = nevra[: -len(arch)]
            break

    # Find release (last segment after '-')
    last_dash = nevra.rfind("-")
    if last_dash == -1:
        return ("0", "", "")
    rel_part = nevra[last_dash + 1:]
    remainder = nevra[:last_dash]

    # Find version (next segment before release, starts with digit or epoch like "1:...")
    second_dash = remainder.rfind("-")
    if second_dash == -1:
        return ("0", "", "")
    ver_part = remainder[second_dash + 1:]

    # Validate: version should start with a digit or an epoch (digit + colon)
    # If it doesn't, this isn't a proper NEVRA — skip
    first_char = ver_part[0] if ver_part else ""
    if not first_char.isdigit():
        return ("0", "", "")

    # Extract epoch from version part
    if ":" in ver_part:
        epoch, version = ver_part.split(":", 1)
    else:
        epoch = "0"
        version = ver_part

    return (epoch, version, rel_part)


def get_closed_cves_redhat(component: Component, rate_limit: float = 0.5) -> List[ClosedCVE]:
    """
    Query Red Hat Security Data API for CVEs fixed in a component's version.

    Paginates through the list endpoint and uses affected_packages from the
    list response to check version ranges without needing per-CVE detail fetches.
    """
    closed_cves = []
    rhel_version = component.distro_version or "8"
    product_match = f"Red Hat Enterprise Linux {rhel_version}"
    el_suffix = f".el{rhel_version}"

    # Map to source package name for API query
    query_name = _get_source_package_name(component.name)

    # Step 1: Paginate through CVE list for this package, filtered by product
    all_cve_entries = []
    for page in range(1, MAX_PAGES + 1):
        try:
            url = f"{BASE_URL}/cve.json"
            params = {
                "package": query_name,
                "product": product_match,
                "per_page": 100,
                "page": page,
            }
            resp = requests.get(url, params=params, timeout=30)
            resp.raise_for_status()
            page_results = resp.json()
        except (requests.RequestException, ValueError) as e:
            logger.warning(f"Red Hat API error for {component.name} page {page}: {e}")
            break

        if not page_results:
            break

        all_cve_entries.extend(page_results)
        time.sleep(rate_limit)

        if len(page_results) < 100:
            break  # Last page

    logger.info(f"Red Hat API: {query_name} → {len(all_cve_entries)} CVEs for RHEL {rhel_version}")

    # Step 2: Pre-filter using affected_packages from list response (no detail fetch needed)
    # The list response includes affected_packages with NEVRAs like "openssl-1:1.1.1k-15.el8_10"
    installed_ver = component.version
    installed_rel = component.release or ""
    installed_epoch = component.epoch or "0"
    inst_full = f"{installed_epoch}:{installed_ver}-{installed_rel}" if installed_rel else f"{installed_epoch}:{installed_ver}"

    prev_full = None
    if component.previous_version:
        prev_epoch = component.previous_epoch or "0"
        prev_rel = component.previous_release or ""
        prev_full = f"{prev_epoch}:{component.previous_version}-{prev_rel}" if prev_rel else f"{prev_epoch}:{component.previous_version}"

    for cve_entry in all_cve_entries:
        cve_id = cve_entry.get("CVE", "")
        if not cve_id:
            continue

        # Check affected_packages for a matching RHEL version entry
        affected_pkgs = cve_entry.get("affected_packages", [])
        matched = False
        for pkg in affected_pkgs:
            # Filter to packages matching our EL version (e.g. .el8)
            if el_suffix not in pkg:
                continue
            # Extract package name from NEVRA
            pkg_name = _extract_rpm_name_from_nevra(pkg)
            if pkg_name != component.name and pkg_name != query_name:
                continue

            # Parse fix version and compare
            fix_epoch, fix_ver, fix_rel = _parse_fix_version(pkg)
            if not fix_ver:
                continue
            fix_full = f"{fix_epoch}:{fix_ver}-{fix_rel}" if fix_rel else f"{fix_epoch}:{fix_ver}"

            # Check: fix_version <= installed_version
            if not is_version_lte(fix_full, inst_full, distro="rocky"):
                continue

            # Range check: fix must be AFTER previous version
            if prev_full:
                if is_version_lte(fix_full, prev_full, distro="rocky"):
                    continue  # Already fixed in old version
            else:
                # Fresh install: exact match only
                if fix_full != inst_full:
                    continue

            # This CVE is closed by our upgrade
            severity = cve_entry.get("severity", "").lower()
            public_date = cve_entry.get("public_date", "")
            if public_date:
                public_date = public_date[:10]

            closed_cves.append(ClosedCVE(
                cve_id=cve_id,
                component=component,
                source="distro",
                backported="yes",
                severity=severity,
                published_date=public_date,
            ))
            matched = True
            break  # Found match for this CVE, move to next

    logger.info(f"Red Hat API: {component.name} → {len(closed_cves)} closed CVEs")
    return closed_cves

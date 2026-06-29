import logging
from typing import List, Dict, Optional
import requests

from hermes.models import Component, ClosedCVE
from hermes.version_compare import alpine_version_compare

logger = logging.getLogger(__name__)

SECDB_BASE_URL = "https://secdb.alpinelinux.org"

# Cache: branch -> {repo -> parsed_data}
_secdb_cache: Dict[str, Dict[str, list]] = {}

# Common sub-package to source-package mappings for Alpine secdb lookups.
# secdb only lists source packages; sub-packages inherit their CVEs.
_SUBPACKAGE_MAP = {
    "libcrypto3": "openssl",
    "libssl3": "openssl",
    "libcurl": "curl",
    "xz-libs": "xz",
    "xz-dev": "xz",
    "musl-utils": "musl",
    "busybox-binsh": "busybox",
    "ssl_client": "busybox",
    "libxml2": "libxml2",
    "nghttp2-libs": "nghttp2",
    "zlib": "zlib",
    "zstd-libs": "zstd",
    "ca-certificates-bundle": "ca-certificates",
}


def _download_secdb(branch: str, repo: str) -> Optional[dict]:
    """Download and cache Alpine secdb JSON for a branch/repo."""
    cache_key = branch
    if cache_key in _secdb_cache and repo in _secdb_cache[cache_key]:
        return _secdb_cache[cache_key][repo]

    url = f"{SECDB_BASE_URL}/{branch}/{repo}.json"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        logger.error(f"Failed to download Alpine secdb {url}: {e}")
        return None

    if cache_key not in _secdb_cache:
        _secdb_cache[cache_key] = {}
    _secdb_cache[cache_key][repo] = data
    return data


def _find_package_secfixes(secdb_data: dict, package_name: str) -> Optional[dict]:
    """Find the secfixes map for a package in the secdb data."""
    packages = secdb_data.get("packages", [])
    for pkg_entry in packages:
        pkg = pkg_entry.get("pkg", {})
        if pkg.get("name") == package_name:
            return pkg.get("secfixes", {})
    return None


def get_closed_cves_alpine(component: Component) -> List[ClosedCVE]:
    """
    Query Alpine secdb for CVEs fixed in a component's version or earlier.

    Logic: collect all CVEs from secfixes where fix_version <= current_version.
    Handles sub-package to source-package mapping.
    """
    closed_cves = []
    branch = component.distro_version  # e.g., "v3.20"

    if not branch:
        logger.warning(f"No Alpine branch for {component.name}, skipping CVE lookup")
        return closed_cves

    # Map sub-package names to source package names
    lookup_name = _SUBPACKAGE_MAP.get(component.name, component.name)

    # Try both main and community repos
    secfixes = None
    for repo in ("main", "community"):
        secdb_data = _download_secdb(branch, repo)
        if secdb_data is None:
            continue
        secfixes = _find_package_secfixes(secdb_data, lookup_name)
        if secfixes is not None:
            break

    if secfixes is None:
        logger.debug(f"Package {component.name} not found in Alpine secdb {branch}")
        return closed_cves

    # Collect CVEs where fix version <= current version
    # - Upgraded packages: only include CVEs fixed AFTER the previous version
    #   (fix_version > previous AND fix_version <= current)
    # - Fresh installs: only include CVEs fixed in the EXACT installed version
    #   (fix_version == current)
    current_version = component.version
    previous_version = component.previous_version  # empty string for fresh installs
    for fix_version, cve_list in secfixes.items():
        if previous_version:
            # Upgraded: range check (previous < fix <= current)
            if alpine_version_compare(fix_version, current_version) > 0:
                continue
            if alpine_version_compare(fix_version, previous_version) <= 0:
                continue
        else:
            # Fresh install: exact version match only
            if alpine_version_compare(fix_version, current_version) != 0:
                continue
        for cve_entry in cve_list:
                # secdb entries can be "CVE-XXXX-YYYY" or "CVE-XXXX-YYYY ADVISORY"
                cve_id = cve_entry.split()[0] if cve_entry else ""
                if cve_id.startswith("CVE-"):
                    closed_cves.append(ClosedCVE(
                        cve_id=cve_id,
                        component=component,
                        source="distro",
                        backported="yes",
                    ))

    logger.info(f"Alpine secdb: {component.name} → {len(closed_cves)} closed CVEs")
    return closed_cves

import logging
from typing import List, Optional
import requests

from hermes.models import ClosedCVE

logger = logging.getLogger(__name__)

OSV_API_BASE = "https://api.osv.dev/v1"


def _cvss_to_severity(score: float) -> str:
    """Map CVSS v3 score to severity label."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0:
        return "low"
    return ""


def enrich_cve(cve: ClosedCVE) -> ClosedCVE:
    """
    Enrich a single CVE with metadata from OSV.dev.
    Updates severity, published_date, modified_date in place.
    """
    try:
        url = f"{OSV_API_BASE}/vulns/{cve.cve_id}"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 404:
            logger.debug(f"CVE {cve.cve_id} not found in OSV.dev")
            return cve
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        logger.debug(f"OSV.dev error for {cve.cve_id}: {e}")
        return cve

    # Extract published and modified dates
    if not cve.published_date:
        published = data.get("published", "")
        if published:
            cve.published_date = published[:10]

    modified = data.get("modified", "")
    if modified:
        cve.modified_date = modified[:10]

    # Extract severity from CVSS
    if not cve.severity:
        severity_list = data.get("severity", [])
        for sev in severity_list:
            if sev.get("type") == "CVSS_V3":
                score_str = sev.get("score", "")
                # OSV returns the CVSS vector string; extract base score if numeric
                if score_str:
                    # Try to find base score in CVSS vector (some have /BS:X.X appended)
                    # Otherwise use the vector metrics to approximate severity
                    import re
                    bs_match = re.search(r"(\d+\.\d+)$", score_str)
                    if bs_match:
                        score = float(bs_match.group(1))
                        cve.severity = _cvss_to_severity(score)
                    else:
                        # Map from vector: if AV:N + AC:L → likely high/critical
                        if "AV:N" in score_str and "AC:L" in score_str:
                            if "C:H" in score_str or "I:H" in score_str:
                                cve.severity = "high"
                            else:
                                cve.severity = "medium"
                        elif "AV:N" in score_str:
                            cve.severity = "medium"
                        else:
                            cve.severity = "low"
                break

        # Try from database_specific.severity
        if not cve.severity:
            db_specific = data.get("database_specific", {})
            if db_specific.get("severity"):
                cve.severity = db_specific["severity"].lower()

    return cve


def enrich_cves(cves: List[ClosedCVE]) -> List[ClosedCVE]:
    """Enrich a list of CVEs with OSV.dev metadata."""
    for cve in cves:
        enrich_cve(cve)
    return cves


def find_upstream_cves(package_name: str, ecosystem: str, current_version: str) -> List[str]:
    """
    Query OSV.dev for CVEs affecting a package that may be fixed upstream.
    Returns CVE IDs not already found via distro sources.

    This is for cross-checking: find CVEs the maintainer has fixed but
    the distro hasn't backported.
    """
    try:
        url = f"{OSV_API_BASE}/query"
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            },
            "version": current_version,
        }
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        logger.debug(f"OSV.dev query error for {package_name}: {e}")
        return []

    # Return CVE IDs from the response
    cve_ids = []
    for vuln in data.get("vulns", []):
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_ids.append(alias)
                break
        else:
            vuln_id = vuln.get("id", "")
            if vuln_id.startswith("CVE-"):
                cve_ids.append(vuln_id)

    return cve_ids

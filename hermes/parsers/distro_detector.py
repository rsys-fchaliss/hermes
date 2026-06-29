import re
import os
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Alpine: fetch https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/APKINDEX.tar.gz
ALPINE_URL_PATTERN = re.compile(
    r"dl-cdn\.alpinelinux\.org/alpine/(v\d+\.\d+)/"
)

# Rocky/RHEL: FROM docker.io/library/rockylinux:8
ROCKY_FROM_PATTERN = re.compile(
    r"FROM\s+docker\.io/library/rockylinux:(\d+)"
)

# .el8, .el9 in package versions
EL_VERSION_PATTERN = re.compile(r"\.el(\d+)")

# Rocky Linux 8 - BaseOS
ROCKY_REPO_PATTERN = re.compile(r"Rocky Linux (\d+)")


def detect_distro(log_content: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Detect distro type and version from build log content.

    Returns:
        (distro, version) tuple. distro is 'alpine' or 'rocky', version is
        the branch (e.g. 'v3.20') for Alpine or major version (e.g. '8') for Rocky.
        Returns (None, None) if unrecognized.
    """
    # Check for Alpine first (more specific signal)
    match = ALPINE_URL_PATTERN.search(log_content)
    if match:
        return "alpine", match.group(1)

    # Check for Rocky/RHEL
    match = ROCKY_FROM_PATTERN.search(log_content)
    if match:
        return "rocky", match.group(1)

    match = ROCKY_REPO_PATTERN.search(log_content)
    if match:
        return "rocky", match.group(1)

    match = EL_VERSION_PATTERN.search(log_content)
    if match:
        return "rocky", match.group(1)

    return None, None


def extract_container_name(log_filename: str) -> str:
    """
    Extract container name from log filename.
    Format: log-20260610021843-annlab → annlab
    """
    basename = os.path.basename(log_filename)
    # Split on '-' and take everything after the timestamp
    # Format: log-YYYYMMDDHHMMSS-name
    parts = basename.split("-", 2)
    if len(parts) >= 3:
        return parts[2]
    return basename

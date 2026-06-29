import re
import logging
from typing import List
from hermes.models import Component

logger = logging.getLogger(__name__)

# BuildKit prefix: #7 1.292
BUILDKIT_PREFIX = re.compile(r"^#\d+\s+[\d.]+\s+")

# (1/36) Installing fstrm (0.6.1-r4)
APK_INSTALL_PATTERN = re.compile(
    r"\(\d+/\d+\)\s+Installing\s+(\S+)\s+\((\S+)\)"
)

# (1/11) Upgrading musl (1.2.5-r2 -> 1.2.5-r3)
APK_UPGRADE_PATTERN = re.compile(
    r"\(\d+/\d+\)\s+Upgrading\s+(\S+)\s+\((\S+)\s+->\s+(\S+)\)"
)


def strip_buildkit_prefix(line: str) -> str:
    """Remove Docker BuildKit step prefix from a log line."""
    return BUILDKIT_PREFIX.sub("", line)


def parse_apk_log(log_content: str, distro_version: str = "") -> List[Component]:
    """
    Parse an Alpine apk build log to extract components.

    Handles both Installing and Upgrading lines. For upgrades, uses the new version.
    Deduplicates by name, keeping the latest version seen.
    """
    components = {}  # name -> Component

    for raw_line in log_content.splitlines():
        line = strip_buildkit_prefix(raw_line)

        # Check for upgrade (has old -> new)
        match = APK_UPGRADE_PATTERN.search(line)
        if match:
            name = match.group(1)
            old_version = match.group(2)
            new_version = match.group(3)
            components[name] = Component(
                name=name,
                version=new_version,
                previous_version=old_version,
                was_upgraded=True,
                distro="alpine",
                distro_version=distro_version,
            )
            continue

        # Check for install
        match = APK_INSTALL_PATTERN.search(line)
        if match:
            name = match.group(1)
            version = match.group(2)
            components[name] = Component(
                name=name,
                version=version,
                distro="alpine",
                distro_version=distro_version,
            )
            continue

    logger.info(f"Parsed {len(components)} Alpine packages")
    return list(components.values())

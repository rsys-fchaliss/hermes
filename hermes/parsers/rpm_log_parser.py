import re
import logging
from typing import List
from hermes.models import Component

logger = logging.getLogger(__name__)

# BuildKit prefix: #6 162.0   or #7 4.308
BUILDKIT_PREFIX = re.compile(r"^#\d+\s+[\d.]+\s+")

# NEVRA architectures
KNOWN_ARCHES = (".x86_64", ".noarch", ".i686", ".aarch64", ".ppc64le", ".s390x")


def strip_buildkit_prefix(line: str) -> str:
    """Remove Docker BuildKit step prefix from a log line."""
    return BUILDKIT_PREFIX.sub("", line)


def parse_nevra(nevra_str: str) -> Component:
    """
    Parse an RPM NEVRA string into a Component.

    Format: name-[epoch:]version-release.arch
    Example: openssl-libs-1:1.1.1k-15.el8_10.x86_64
    
    Strategy:
    1. Strip .arch suffix
    2. Right-split on last '-' for release
    3. Right-split remainder on last '-' for epoch:version
    4. Remainder is name
    """
    s = nevra_str.strip()

    # Strip architecture
    arch = ""
    for a in KNOWN_ARCHES:
        if s.endswith(a):
            arch = a[1:]  # remove leading dot
            s = s[: -len(a)]
            break

    # Right-split on last '-' to get release
    last_dash = s.rfind("-")
    if last_dash == -1:
        return Component(name=s, version="", arch=arch, distro="rocky")

    release = s[last_dash + 1:]
    remainder = s[:last_dash]

    # Right-split remainder on last '-' to get epoch:version
    last_dash = remainder.rfind("-")
    if last_dash == -1:
        # No name-version separator found; treat whole thing as name
        return Component(name=remainder, version=release, arch=arch, distro="rocky")

    epoch_version = remainder[last_dash + 1:]
    name = remainder[:last_dash]

    # Split epoch:version on ':'
    epoch = "0"
    version = epoch_version
    if ":" in epoch_version:
        epoch, version = epoch_version.split(":", 1)

    return Component(
        name=name,
        version=version,
        release=release,
        epoch=epoch,
        arch=arch,
        distro="rocky",
    )


def parse_rpm_log(log_content: str, distro_version: str = "") -> List[Component]:
    """
    Parse an RPM-based build log to extract components from Upgraded: and Installed: blocks.

    Also parses transaction 'Cleanup' lines to capture previous versions for upgraded packages.
    Returns a deduplicated list of Components (latest version wins).
    """
    components = {}  # name -> Component (dedup by name, keep last)
    old_versions = {}  # name -> (epoch, version, release) from Cleanup lines
    lines = log_content.splitlines()
    in_block = False
    block_type = None  # "upgraded" or "installed"

    # Regex for transaction lines: "  Cleanup          : openssl-libs-1:1.1.1k-12.el8_9.x86_64   2/4"
    cleanup_pattern = re.compile(r"^\s*Cleanup\s*:\s*(\S+)")

    for raw_line in lines:
        line = strip_buildkit_prefix(raw_line).rstrip()

        # Parse Cleanup lines to capture previous versions
        cleanup_match = cleanup_pattern.match(line)
        if cleanup_match:
            old_comp = parse_nevra(cleanup_match.group(1))
            if old_comp.name:
                old_versions[old_comp.name] = (old_comp.epoch, old_comp.version, old_comp.release)
            continue

        # Detect start of summary block
        if line.startswith("Upgraded:"):
            in_block = True
            block_type = "upgraded"
            continue
        elif line.startswith("Installed:"):
            in_block = True
            block_type = "installed"
            continue

        # Detect end of block (empty line, "Complete!", or next section)
        if in_block:
            stripped = line.strip()
            if not stripped or stripped.startswith("Complete!") or stripped.startswith("Last metadata"):
                in_block = False
                block_type = None
                continue

            # Parse the NEVRA on this line
            nevra_str = stripped
            if not nevra_str:
                continue

            comp = parse_nevra(nevra_str)
            if comp.name:
                comp.distro = "rocky"
                comp.distro_version = distro_version
                comp.was_upgraded = (block_type == "upgraded")
                # Attach previous version if this was an upgrade
                if block_type == "upgraded" and comp.name in old_versions:
                    old_epoch, old_ver, old_rel = old_versions[comp.name]
                    comp.previous_epoch = old_epoch
                    comp.previous_version = old_ver
                    comp.previous_release = old_rel
                components[comp.name] = comp

    logger.info(f"Parsed {len(components)} RPM packages")
    return list(components.values())

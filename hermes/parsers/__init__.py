import logging
from typing import List, Tuple, Optional
from hermes.models import Component
from hermes.parsers.distro_detector import detect_distro, extract_container_name
from hermes.parsers.rpm_log_parser import parse_rpm_log
from hermes.parsers.apk_log_parser import parse_apk_log

logger = logging.getLogger(__name__)


def parse_build_log(log_content: str, log_filename: str) -> Tuple[Optional[str], Optional[str], str, List[Component]]:
    """
    Parse a build log file and return extracted components.

    Returns:
        (distro, distro_version, container_name, components)
    """
    distro, distro_version = detect_distro(log_content)
    container_name = extract_container_name(log_filename)

    if distro is None:
        logger.warning(f"Unknown distro for container '{container_name}' ({log_filename}), skipping")
        return None, None, container_name, []

    if distro == "alpine":
        components = parse_apk_log(log_content, distro_version or "")
    elif distro == "rocky":
        components = parse_rpm_log(log_content, distro_version or "")
    else:
        logger.warning(f"Unsupported distro '{distro}' for container '{container_name}', skipping")
        return distro, distro_version, container_name, []

    return distro, distro_version, container_name, components

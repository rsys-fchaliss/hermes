import re
from typing import List, Tuple


def _split_segments(version_str: str) -> List[Tuple[bool, str]]:
    """
    Split a version string into alternating numeric and non-numeric segments.
    Returns list of (is_numeric, value) tuples.
    """
    segments = []
    for part in re.findall(r"(\d+|[a-zA-Z]+|[^a-zA-Z0-9]+)", version_str):
        is_numeric = part.isdigit()
        segments.append((is_numeric, part))
    return segments


def compare_version_strings(v1: str, v2: str) -> int:
    """
    Compare two version strings segment by segment.
    Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
    """
    segs1 = _split_segments(v1)
    segs2 = _split_segments(v2)

    for i in range(max(len(segs1), len(segs2))):
        if i >= len(segs1):
            return -1
        if i >= len(segs2):
            return 1

        is_num1, val1 = segs1[i]
        is_num2, val2 = segs2[i]

        if is_num1 and is_num2:
            n1, n2 = int(val1), int(val2)
            if n1 < n2:
                return -1
            if n1 > n2:
                return 1
        elif is_num1 != is_num2:
            # Numeric segments sort after alphabetic in RPM
            if is_num1:
                return 1
            return -1
        else:
            if val1 < val2:
                return -1
            if val1 > val2:
                return 1

    return 0


def rpm_version_compare(epoch1: str, ver1: str, rel1: str,
                        epoch2: str, ver2: str, rel2: str) -> int:
    """
    Compare two RPM versions using epoch:version-release.
    Returns: -1 if first < second, 0 if equal, 1 if first > second
    """
    # Compare epochs first
    e1 = int(epoch1) if epoch1 else 0
    e2 = int(epoch2) if epoch2 else 0
    if e1 != e2:
        return -1 if e1 < e2 else 1

    # Compare versions
    result = compare_version_strings(ver1, ver2)
    if result != 0:
        return result

    # Compare releases
    return compare_version_strings(rel1, rel2)


def alpine_version_compare(v1: str, v2: str) -> int:
    """
    Compare two Alpine package versions.
    Format: X.Y.Z-rN where -rN is the Alpine revision.

    Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
    """
    # Split on -r to separate upstream version from Alpine revision
    def split_alpine_version(v):
        # Handle versions like "1.34-r2", "1.2.5-r3", "20240705-r0"
        match = re.match(r"^(.*)-r(\d+)$", v)
        if match:
            return match.group(1), int(match.group(2))
        return v, 0

    upstream1, rev1 = split_alpine_version(v1)
    upstream2, rev2 = split_alpine_version(v2)

    result = compare_version_strings(upstream1, upstream2)
    if result != 0:
        return result

    # Compare Alpine revisions
    if rev1 < rev2:
        return -1
    if rev1 > rev2:
        return 1
    return 0


def is_version_lte(fix_version: str, current_version: str, distro: str) -> bool:
    """Check if fix_version <= current_version for the given distro."""
    if distro == "alpine":
        return alpine_version_compare(fix_version, current_version) <= 0
    else:
        # For RPM, parse epoch:version-release format
        def _parse_evr(s):
            epoch = "0"
            if ":" in s:
                epoch, s = s.split(":", 1)
            if "-" in s:
                ver, rel = s.rsplit("-", 1)
            else:
                ver, rel = s, ""
            return epoch, ver, rel

        e1, v1, r1 = _parse_evr(fix_version)
        e2, v2, r2 = _parse_evr(current_version)
        return rpm_version_compare(e1, v1, r1, e2, v2, r2) <= 0

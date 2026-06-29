from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Component:
    name: str
    version: str
    release: str = ""
    epoch: str = "0"
    arch: str = ""
    distro: str = ""
    distro_version: str = ""
    previous_version: str = ""
    previous_release: str = ""
    previous_epoch: str = ""
    was_upgraded: bool = False  # True if from Upgraded:/Upgrading block (even without old version data)

    @property
    def full_version(self) -> str:
        """Return the full version string as it appears in the package manager."""
        if self.distro == "alpine":
            return self.version
        # RPM: epoch:version-release
        parts = []
        if self.epoch and self.epoch != "0":
            parts.append(f"{self.epoch}:{self.version}")
        else:
            parts.append(self.version)
        if self.release:
            parts.append(f"-{self.release}")
        return "".join(parts)

    @property
    def display_name(self) -> str:
        """Return the component name with version for CSV output."""
        if self.distro == "alpine":
            return f"{self.name}-{self.version}"
        # RPM NEVRA without arch
        evr = self.full_version
        return f"{self.name}-{evr}"


@dataclass
class ClosedCVE:
    cve_id: str
    component: Component
    source: str = "distro"  # "distro" or "maintainer"
    backported: str = "yes"  # "yes" or "no"
    severity: str = ""
    published_date: str = ""
    modified_date: str = ""


@dataclass
class ContainerResult:
    container_name: str
    distro: str
    distro_version: str
    components: list = field(default_factory=list)
    closed_cves: list = field(default_factory=list)

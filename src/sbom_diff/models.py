"""Immutable data types returned by the library."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ChangeKind = Literal["upgrade", "downgrade", "changed"]

CATEGORIES: tuple[str, ...] = (
    "added",
    "removed",
    "upgrade",
    "downgrade",
    "changed",
    "license",
)


@dataclass(frozen=True)
class Component:
    """A dependency listed in an SBOM.

    ``key`` is the normalised identity used to match components across SBOMs.
    """

    key: str
    name: str
    group: str = ""
    version: str = ""
    purl: str = ""
    licenses: tuple[str, ...] = ()


@dataclass(frozen=True)
class ComponentEntry:
    """A component key present on only one side of the comparison.

    ``version`` is the comma-joined sorted set of versions seen for the key.
    """

    key: str
    version: str
    licenses: tuple[str, ...] = ()


@dataclass(frozen=True)
class VersionChange:
    """A key present on both sides whose version set differs."""

    key: str
    before: str
    after: str
    kind: ChangeKind


@dataclass(frozen=True)
class LicenseChange:
    """A key present on both sides whose license set differs."""

    key: str
    before: tuple[str, ...]
    after: tuple[str, ...]


@dataclass(frozen=True)
class SbomDiff:
    """The result of comparing two SBOMs; every list is sorted by key."""

    added: list[ComponentEntry] = field(default_factory=list)
    removed: list[ComponentEntry] = field(default_factory=list)
    changed: list[VersionChange] = field(default_factory=list)
    license_changes: list[LicenseChange] = field(default_factory=list)

    def category_counts(self) -> dict[str, int]:
        """Return how many items each ``--fail-on`` category currently holds."""
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "upgrade": self._count("upgrade"),
            "downgrade": self._count("downgrade"),
            "changed": self._count("changed"),
            "license": len(self.license_changes),
        }

    def _count(self, kind: ChangeKind) -> int:
        return sum(1 for change in self.changed if change.kind == kind)

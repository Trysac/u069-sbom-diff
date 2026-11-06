"""Compute the difference between two component lists."""

from __future__ import annotations

from collections.abc import Iterable

from sbom_diff.models import (
    ChangeKind,
    Component,
    ComponentEntry,
    LicenseChange,
    SbomDiff,
    VersionChange,
)
from sbom_diff.versions import compare_versions

_Index = dict[str, set[str]]


def _index(components: Iterable[Component]) -> tuple[_Index, _Index]:
    versions: _Index = {}
    licenses: _Index = {}
    for component in components:
        versions.setdefault(component.key, set()).add(component.version)
        licenses.setdefault(component.key, set()).update(component.licenses)
    return versions, licenses


def _join(versions: set[str]) -> str:
    return ",".join(sorted(versions))


def _kind(before: set[str], after: set[str]) -> ChangeKind:
    if len(before) == 1 and len(after) == 1:
        result = compare_versions(next(iter(before)), next(iter(after)))
        if result == -1:
            return "upgrade"
        if result == 1:
            return "downgrade"
    return "changed"


def _entries(keys: Iterable[str], versions: _Index, licenses: _Index) -> list[ComponentEntry]:
    return [
        ComponentEntry(key, _join(versions[key]), tuple(sorted(licenses[key])))
        for key in sorted(keys)
    ]


def diff(base: Iterable[Component], head: Iterable[Component]) -> SbomDiff:
    """Compare the components of a base SBOM with those of a head SBOM.

    Components are matched by ``Component.key``. A key with several versions on one side is a
    version set: when the sets differ the change kind is ``changed`` and the versions are
    reported comma-joined and sorted. Every list of the result is sorted by key.

    Raises:
        SbomDiffError: code ``too_large`` if a version exceeds 256 characters.
    """
    base_versions, base_licenses = _index(base)
    head_versions, head_licenses = _index(head)
    added_keys = head_versions.keys() - base_versions.keys()
    removed_keys = base_versions.keys() - head_versions.keys()
    changed: list[VersionChange] = []
    license_changes: list[LicenseChange] = []
    for key in sorted(base_versions.keys() & head_versions.keys()):
        before = base_versions[key]
        after = head_versions[key]
        if before != after:
            kind = _kind(before, after)
            changed.append(VersionChange(key, _join(before), _join(after), kind))
        old_licenses = tuple(sorted(base_licenses[key]))
        new_licenses = tuple(sorted(head_licenses[key]))
        if old_licenses != new_licenses:
            license_changes.append(LicenseChange(key, old_licenses, new_licenses))
    return SbomDiff(
        added=_entries(added_keys, head_versions, head_licenses),
        removed=_entries(removed_keys, base_versions, base_licenses),
        changed=changed,
        license_changes=license_changes,
    )

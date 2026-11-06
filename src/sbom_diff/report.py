"""Render an SbomDiff as text or JSON."""

from __future__ import annotations

import json
from typing import Literal

from sbom_diff.models import ComponentEntry, LicenseChange, SbomDiff, VersionChange

_NONE = "(none)"


def _clean(text: str) -> str:
    """Escape non-printable characters so SBOM data cannot forge report lines."""
    return "".join(ch if ch.isprintable() else f"\\u{ord(ch):04x}" for ch in text)


def _label(text: str) -> str:
    return _clean(text) if text else _NONE


def _licenses(values: tuple[str, ...]) -> str:
    return ", ".join(_clean(value) for value in values) if values else _NONE


def _entry_line(marker: str, entry: ComponentEntry) -> str:
    line = f"  {marker} {_clean(entry.key)} {_label(entry.version)}"
    if entry.licenses:
        line += f" [{_licenses(entry.licenses)}]"
    return line


def _change_line(marker: str, change: VersionChange) -> str:
    return f"  {marker} {_clean(change.key)} {_label(change.before)} -> {_label(change.after)}"


def _license_line(change: LicenseChange) -> str:
    before = _licenses(change.before)
    after = _licenses(change.after)
    return f"  ! {_clean(change.key)} {before} -> {after}"


def _render_text(result: SbomDiff) -> str:
    lines: list[str] = []

    def section(title: str, items: list[str]) -> None:
        if items:
            lines.append(f"{title} ({len(items)})")
            lines.extend(items)

    section("Added", [_entry_line("+", entry) for entry in result.added])
    section("Removed", [_entry_line("-", entry) for entry in result.removed])
    for title, kind, marker in (
        ("Upgraded", "upgrade", "^"),
        ("Downgraded", "downgrade", "v"),
        ("Changed", "changed", "~"),
    ):
        section(title, [_change_line(marker, c) for c in result.changed if c.kind == kind])
    section("License changes", [_license_line(change) for change in result.license_changes])
    return "\n".join(lines) if lines else "No differences."


def _entry_dict(entry: ComponentEntry) -> dict[str, object]:
    return {"key": entry.key, "licenses": list(entry.licenses), "version": entry.version}


def _render_json(result: SbomDiff) -> str:
    payload: dict[str, object] = {
        "added": [_entry_dict(entry) for entry in result.added],
        "removed": [_entry_dict(entry) for entry in result.removed],
        "changed": [
            {"key": c.key, "before": c.before, "after": c.after, "kind": c.kind}
            for c in result.changed
        ],
        "license_changes": [
            {"key": c.key, "before": list(c.before), "after": list(c.after)}
            for c in result.license_changes
        ],
    }
    return json.dumps(payload, sort_keys=True, indent=2)


def render(result: SbomDiff, fmt: Literal["text", "json"]) -> str:
    """Render ``result`` as human-readable ``text`` or as ``json`` (sorted keys, indent 2).

    The returned string has no trailing newline. Text output escapes control characters.

    Raises:
        ValueError: if ``fmt`` is neither ``text`` nor ``json``.
    """
    if fmt == "text":
        return _render_text(result)
    if fmt == "json":
        return _render_json(result)
    raise ValueError("fmt must be 'text' or 'json'")

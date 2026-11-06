"""Tests for diff, render and the package surface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import sbom_diff
from sbom_diff import (
    Component,
    ComponentEntry,
    LicenseChange,
    SbomDiff,
    VersionChange,
    diff,
    load_sbom,
    render,
)

FIXTURES = Path(__file__).parent / "fixtures"

TEXT_LINES = [
    "Added (1)",
    "  + pkg:pypi/requests-x 1",
    "Removed (1)",
    "  - pkg:pypi/old 1.0.0",
    "Upgraded (2)",
    "  ^ nested 1.0 -> 1.1",
    "  ^ pkg:pypi/requests 2.0 -> 2.1",
    "Downgraded (1)",
    "  v pkg:npm/dg 2.0.0 -> 1.0.0",
    "Changed (1)",
    "  ~ org/multi 1.0,2.0 -> 2.0",
    "License changes (1)",
    "  ! pkg:npm/lic MIT -> Apache-2.0 OR MIT",
]

EMPTY_JSON_LINES = [
    "{",
    '  "added": [],',
    '  "changed": [],',
    '  "license_changes": [],',
    '  "removed": []',
    "}",
]


def lib(name: str, version: str | None = None, **extra: Any) -> dict[str, Any]:
    component: dict[str, Any] = {"type": "library", "name": name}
    if version is not None:
        component["version"] = version
    component.update(extra)
    return component


def sbom(
    components: list[dict[str, Any]],
    *,
    subject: dict[str, Any] | None = None,
) -> str:
    document: dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1}
    if subject is not None:
        document["metadata"] = {"component": subject}
    document["components"] = components
    return json.dumps(document)


def comp(key: str, version: str = "1.0", licenses: tuple[str, ...] = ()) -> Component:
    return Component(key=key, name=key, version=version, licenses=licenses)


def fixture_diff() -> SbomDiff:
    return diff(load_sbom(FIXTURES / "base.json"), load_sbom(FIXTURES / "head.json"))


def test_requests_is_an_upgrade_and_requests_x_is_added() -> None:
    base_text = sbom(
        [lib("Requests", "2.0", purl="pkg:pypi/Requests@2.0")],
        subject=lib("subject", "1", purl="pkg:pypi/subject@1"),
    )
    head_text = sbom(
        [
            lib("requests_x", "1", purl="pkg:pypi/requests_x@1"),
            lib("requests", "2.1", purl="pkg:pypi/requests@2.1"),
        ],
        subject=lib("subject", "2", purl="pkg:pypi/subject@2"),
    )
    result = diff(load_sbom(base_text), load_sbom(head_text))
    assert result.changed == [VersionChange("pkg:pypi/requests", "2.0", "2.1", "upgrade")]
    assert [entry.key for entry in result.added] == ["pkg:pypi/requests-x"]
    assert result.removed == []
    assert result.license_changes == []


@pytest.mark.parametrize(
    ("before", "after", "kind"),
    [
        ("1.0.0", "1.0.1", "upgrade"),
        ("2.0.0", "1.9.9", "downgrade"),
        ("abc123", "def", "changed"),
        ("1.0.0+b1", "1.0.0", "changed"),
        ("1.2", "1.2.0", "changed"),
        ("1.0.0-rc.1", "1.0.0", "upgrade"),
        ("", "1.0", "changed"),
    ],
)
def test_single_version_change_kind(before: str, after: str, kind: str) -> None:
    result = diff([comp("k", before)], [comp("k", after)])
    assert result.changed == [VersionChange("k", before, after, kind)]


def test_unchanged_versions_are_not_reported() -> None:
    assert diff([comp("k", "1.0")], [comp("k", "1.0")]).changed == []


def test_version_set_difference_is_changed() -> None:
    base = [comp("k", "1.0"), comp("k", "2.0")]
    head = [comp("k", "2.0")]
    assert diff(base, head).changed == [VersionChange("k", "1.0,2.0", "2.0", "changed")]
    assert diff(head, base).changed == [VersionChange("k", "2.0", "1.0,2.0", "changed")]


def test_equal_version_sets_are_not_changes() -> None:
    base = [comp("k", "1.0"), comp("k", "2.0"), comp("k", "2.0")]
    head = [comp("k", "2.0"), comp("k", "1.0")]
    assert diff(base, head).changed == []


def test_license_id_to_expression_is_a_license_change() -> None:
    base_text = sbom([lib("k", "1", licenses=[{"license": {"id": "MIT"}}])])
    head_text = sbom([lib("k", "1", licenses=[{"expression": "Apache-2.0 OR MIT"}])])
    result = diff(load_sbom(base_text), load_sbom(head_text))
    assert result.license_changes == [LicenseChange("k", ("MIT",), ("Apache-2.0 OR MIT",))]
    assert result.changed == []


def test_every_list_is_sorted_by_key() -> None:
    base = [
        comp("z", "1", ("MIT",)),
        comp("b", "1"),
        comp("y", "1"),
        comp("a", "1", ("MIT",)),
    ]
    head = [
        comp("x"),
        comp("c"),
        comp("y", "2"),
        comp("a", "2", ("GPL-3.0-only",)),
        comp("z", "1", ("Apache-2.0",)),
    ]
    result = diff(base, head)
    assert [entry.key for entry in result.added] == ["c", "x"]
    assert [entry.key for entry in result.removed] == ["b"]
    assert [change.key for change in result.changed] == ["a", "y"]
    assert [change.key for change in result.license_changes] == ["a", "z"]


def test_entries_carry_sorted_versions_and_licenses() -> None:
    result = diff([], [comp("k", "1", ("B", "A"))])
    assert result.added == [ComponentEntry("k", "1", ("A", "B"))]
    reverse = diff([comp("k", "1", ("B", "A"))], [])
    assert reverse.removed == [ComponentEntry("k", "1", ("A", "B"))]


def test_licenses_are_merged_across_versions_of_a_key() -> None:
    base = [comp("k", "1", ("A",)), comp("k", "2", ("B",))]
    head = [comp("k", "1", ("A", "B"))]
    result = diff(base, head)
    assert result.license_changes == []
    assert result.changed == [VersionChange("k", "1,2", "1", "changed")]


def test_identical_inputs_produce_an_empty_diff() -> None:
    result = diff([comp("k")], [comp("k")])
    assert result == SbomDiff([], [], [], [])
    counts = result.category_counts()
    assert counts == {
        "added": 0,
        "removed": 0,
        "upgrade": 0,
        "downgrade": 0,
        "changed": 0,
        "license": 0,
    }


def test_fixture_diff_counts() -> None:
    counts = fixture_diff().category_counts()
    assert counts == {
        "added": 1,
        "removed": 1,
        "upgrade": 2,
        "downgrade": 1,
        "changed": 1,
        "license": 1,
    }


def test_json_report_matches_the_golden_file() -> None:
    golden = (FIXTURES / "expected.json").read_text(encoding="utf-8")
    assert render(fixture_diff(), "json") + "\n" == golden
    assert json.loads(golden)["added"][0]["key"] == "pkg:pypi/requests-x"


def test_text_report_matches_expected_lines() -> None:
    assert render(fixture_diff(), "text") == "\n".join(TEXT_LINES)


def test_empty_diff_renders() -> None:
    empty = SbomDiff()
    assert render(empty, "text") == "No differences."
    assert render(empty, "json") == "\n".join(EMPTY_JSON_LINES)


def test_text_report_shows_licenses_and_missing_versions() -> None:
    result = SbomDiff(
        added=[ComponentEntry("k", "1", ("MIT", "X"))],
        removed=[ComponentEntry("r", "", ())],
        changed=[],
        license_changes=[LicenseChange("k", (), ("MIT",))],
    )
    lines = render(result, "text").split("\n")
    assert "  + k 1 [MIT, X]" in lines
    assert "  - r (none)" in lines
    assert "  ! k (none) -> MIT" in lines


def test_text_report_escapes_control_characters() -> None:
    entry = ComponentEntry("evil\nkey\x1b[0m", "1", ())
    result = SbomDiff(added=[entry], removed=[], changed=[], license_changes=[])
    lines = render(result, "text").split("\n")
    assert lines == ["Added (1)", "  + evil\\u000akey\\u001b[0m 1"]


def test_render_rejects_unknown_formats() -> None:
    with pytest.raises(ValueError, match="fmt"):
        render(SbomDiff(), "yaml")  # type: ignore[arg-type]


def test_public_api_surface() -> None:
    assert sbom_diff.__version__ == "0.1.0"
    for name in sbom_diff.__all__:
        assert hasattr(sbom_diff, name)

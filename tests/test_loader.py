"""Tests for load_sbom."""

from __future__ import annotations

import dataclasses
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from sbom_diff import Component, SbomDiffError, load_sbom

BASE = {"bomFormat": "CycloneDX", "specVersion": "1.5"}

FORMAT_ERRORS: list[Any] = [
    [],
    "string",
    5,
    {"specVersion": "1.5"},
    {"bomFormat": "cyclonedx", "specVersion": "1.5"},
    {"bomFormat": "SPDX", "specVersion": "2.3"},
    {**BASE, "components": {}},
    {**BASE, "components": ["x"]},
    {**BASE, "components": [{"type": "library"}]},
    {**BASE, "components": [{"name": 5}]},
    {**BASE, "components": [{"name": ""}]},
    {**BASE, "components": [{"name": "a", "version": 1}]},
    {**BASE, "components": [{"name": "a", "group": 3}]},
    {**BASE, "components": [{"name": "a", "licenses": {}}]},
    {**BASE, "components": [{"name": "a", "licenses": ["MIT"]}]},
    {**BASE, "components": [{"name": "a", "components": "x"}]},
    {**BASE, "components": [{"name": "a", "components": [3]}]},
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
    spec: str = "1.5",
    subject: dict[str, Any] | None = None,
) -> str:
    document: dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": spec, "version": 1}
    if subject is not None:
        document["metadata"] = {"component": subject}
    document["components"] = components
    return json.dumps(document)


def nested(levels: int) -> dict[str, Any]:
    inner: dict[str, Any] | None = None
    for level in range(levels, 0, -1):
        component = lib(f"c{level}", "1")
        if inner is not None:
            component["components"] = [inner]
        inner = component
    assert inner is not None
    return inner


def code_of(source: Path | str, **kwargs: Any) -> str:
    with pytest.raises(SbomDiffError) as info:
        load_sbom(source, **kwargs)
    return info.value.code


def test_flattens_nested_components_and_skips_metadata_component() -> None:
    text = sbom(
        [
            lib("requests", "2.0", purl="pkg:pypi/requests@2.0?x=1#sub"),
            lib(
                "a",
                "1",
                purl="pkg:npm/%40scope/a@1",
                components=[lib("inner", "3", group="org"), lib("bare", "4")],
            ),
        ],
        subject=lib("subject", "9", purl="pkg:pypi/subject@9"),
    )
    components = load_sbom(text)
    keys = [c.key for c in components]
    assert keys == ["pkg:pypi/requests", "pkg:npm/@scope/a", "org/inner", "bare"]


@pytest.mark.parametrize(
    ("purl", "key"),
    [
        ("pkg:pypi/requests@2.0?x=1#sub", "pkg:pypi/requests"),
        ("pkg:npm/%40scope/a@1", "pkg:npm/@scope/a"),
        ("pkg:pypi/Requests@2.0", "pkg:pypi/requests"),
        ("pkg:PyPI/My_Pkg.Name@1", "pkg:pypi/my-pkg-name"),
        ("pkg:pypi/a__b..c--d", "pkg:pypi/a-b-c-d"),
        ("pkg:pypi/%52equests@1", "pkg:pypi/requests"),
        ("pkg:maven/org.apache/commons@1.0?type=jar", "pkg:maven/org.apache/commons"),
        ("pkg:golang/github.com/foo/Bar@v1", "pkg:golang/github.com/foo/Bar"),
        ("pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie", "pkg:deb/debian/curl"),
        ("pkg:npm/Left-Pad@1", "pkg:npm/Left-Pad"),
        ("pkg://npm/a@1", "pkg:npm/a"),
    ],
)
def test_purl_keys(purl: str, key: str) -> None:
    (component,) = load_sbom(sbom([lib("x", "1", purl=purl)]))
    assert component.key == key
    assert component.purl == purl


@pytest.mark.parametrize("purl", ["", "notapurl", "pkg:pypi", "pkg:pypi/", "pkg:/name"])
def test_unusable_purl_falls_back_to_group_and_name(purl: str) -> None:
    (with_group,) = load_sbom(sbom([lib("fallback", "1", group="g", purl=purl)]))
    (without_group,) = load_sbom(sbom([lib("fallback", "1", purl=purl)]))
    assert with_group.key == "g/fallback"
    assert without_group.key == "fallback"


def test_components_without_purl_are_keyed_group_name_or_name() -> None:
    """Keys are 'group/name' with a group, else 'name'."""
    grouped, bare = load_sbom(sbom([lib("n", "1", group="grp"), lib("m", "1")]))
    assert grouped.key == "grp/n"
    assert bare.key == "m"


def test_version_falls_back_to_the_purl_version() -> None:
    (from_purl,) = load_sbom(sbom([lib("x", purl="pkg:pypi/x@1.5")]))
    (explicit,) = load_sbom(sbom([lib("x", "2.0", purl="pkg:pypi/x@1.5")]))
    (bare,) = load_sbom(sbom([lib("x")]))
    assert from_purl.version == "1.5"
    assert explicit.version == "2.0"
    assert bare.version == ""


def test_licenses_are_taken_sorted_and_deduplicated() -> None:
    licenses = [
        {"license": {"id": "MIT"}},
        {"license": {"name": "Custom"}},
        {"license": {"id": "MIT"}},
        {"expression": "Apache-2.0 OR MIT"},
        {"license": {"id": "BSD-3-Clause", "name": "Other"}},
        {"license": {}},
        {"license": {"id": 5}},
    ]
    (component,) = load_sbom(sbom([lib("a", "1", licenses=licenses)]))
    assert component.licenses == ("Apache-2.0 OR MIT", "BSD-3-Clause", "Custom", "MIT")


def test_component_fields_and_immutability() -> None:
    (component,) = load_sbom(sbom([lib("a", "1", group="org", purl="pkg:maven/org/a@1")]))
    assert component == Component("pkg:maven/org/a", "a", "org", "1", "pkg:maven/org/a@1", ())
    with pytest.raises(dataclasses.FrozenInstanceError):
        component.key = "other"


@pytest.mark.parametrize("spec", ["1.4", "1.5", "1.6"])
def test_supported_spec_versions(spec: str) -> None:
    assert load_sbom(sbom([], spec=spec)) == []


def test_missing_components_key_means_no_components() -> None:
    assert load_sbom(json.dumps(BASE)) == []


@pytest.mark.parametrize("document", FORMAT_ERRORS)
def test_format_errors(document: Any) -> None:
    assert code_of(json.dumps(document)) == "format"


def test_spdx_document_is_rejected_with_format_code() -> None:
    text = json.dumps({"bomFormat": "SPDX", "specVersion": "2.3"})
    assert code_of(text) == "format"


@pytest.mark.parametrize("spec", ["1.3", "2.0", "", 1.5, None, "9" * 1000])
def test_unsupported_spec_versions(spec: Any) -> None:
    text = json.dumps({"bomFormat": "CycloneDX", "specVersion": spec})
    assert code_of(text) == "unsupported_version"


def test_spec_version_1_3_is_unsupported() -> None:
    assert code_of(sbom([], spec="1.3")) == "unsupported_version"


def test_error_message_never_quotes_more_than_200_characters() -> None:
    text = json.dumps({"bomFormat": "CycloneDX", "specVersion": "9" * 1000})
    with pytest.raises(SbomDiffError) as info:
        load_sbom(text)
    assert info.value.code == "unsupported_version"
    assert len(str(info.value)) <= 200
    assert "9" * 100 not in str(info.value)
    text = json.dumps({"bomFormat": "X" * 1000, "specVersion": "1.5"})
    with pytest.raises(SbomDiffError) as format_info:
        load_sbom(text)
    assert len(str(format_info.value)) <= 200


def test_error_class_caps_messages_and_exposes_code() -> None:
    error = SbomDiffError("format", "x" * 500)
    assert error.code == "format"
    assert len(str(error)) == 200
    assert str(error).endswith("...")
    assert str(SbomDiffError("too_large", "short")) == "short"


def test_file_larger_than_52_428_800_bytes_is_too_large(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_bytes(b" " * 52_428_801)
    assert code_of(path) == "too_large"


def test_max_bytes_applies_to_bytes_not_characters() -> None:
    text = sbom([])
    size = len(text.encode("utf-8"))
    assert load_sbom(text, max_bytes=size) == []
    assert code_of(text, max_bytes=size - 1) == "too_large"
    assert code_of("\u00e9" * 6, max_bytes=10) == "too_large"
    assert code_of("x" * 11, max_bytes=10) == "too_large"


def test_max_bytes_must_be_positive() -> None:
    with pytest.raises(ValueError, match="max_bytes"):
        load_sbom("{}", max_bytes=0)


def test_component_count_limit() -> None:
    components = [lib("c")] * 100_001
    assert code_of(sbom(components)) == "too_large"
    assert len(load_sbom(sbom(components[:100_000]))) == 100_000


def test_component_depth_limit() -> None:
    assert len(load_sbom(sbom([nested(32)]))) == 32
    assert code_of(sbom([nested(33)])) == "too_deep"


def test_overlong_component_version_is_rejected() -> None:
    assert len(load_sbom(sbom([lib("a", "1" * 256)]))) == 1
    assert code_of(sbom([lib("a", "1" * 257)])) == "too_large"


def test_extreme_json_nesting_is_rejected_before_parsing() -> None:
    assert code_of("[" * 100_000) == "too_deep"
    assert code_of('{"a":' * 50_000) == "too_deep"


def test_brackets_inside_strings_do_not_count_as_depth() -> None:
    note = ('\\"' + "[" * 10) * 50 + "\\"
    document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "note": note}
    assert load_sbom(json.dumps(document)) == []


@pytest.mark.parametrize("text", ["", "{not json", '["unterminated', "[1,]", "NaN extra"])
def test_invalid_json(text: str) -> None:
    assert code_of(text) == "invalid_json"


def test_recursion_error_is_reported_as_too_deep(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_text: str) -> object:
        raise RecursionError

    monkeypatch.setattr(json, "loads", boom)
    assert code_of("{}") == "too_deep"


def test_reads_files_and_rejects_invalid_utf8(tmp_path: Path) -> None:
    text = sbom([lib("a", "1")])
    good = tmp_path / "good.json"
    good.write_text(text, encoding="utf-8")
    assert load_sbom(good) == load_sbom(text)
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"\xff\xfe{}")
    assert code_of(bad) == "invalid_json"


def test_unreadable_paths_are_format_errors(tmp_path: Path) -> None:
    assert code_of(tmp_path / "missing.json") == "format"
    assert code_of(tmp_path) == "format"


def test_utf8_bom_is_accepted(tmp_path: Path) -> None:
    body = sbom([lib("a", "1")])
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + body.encode("utf-8"))
    assert [c.name for c in load_sbom(path)] == ["a"]
    assert [c.name for c in load_sbom("\ufeff" + body)] == ["a"]


def test_library_does_not_configure_logging() -> None:
    before = list(logging.getLogger().handlers)
    load_sbom(sbom([lib("a", "1")]))
    assert logging.getLogger().handlers == before
    handlers = logging.getLogger("sbom_diff").handlers
    assert any(isinstance(handler, logging.NullHandler) for handler in handlers)

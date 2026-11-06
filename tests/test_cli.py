"""Tests for the command line interface."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path
from typing import Any

import pytest

from sbom_diff.__main__ import main

FIXTURES = Path(__file__).parent / "fixtures"


def lib(name: str, version: str | None = None, **extra: Any) -> dict[str, Any]:
    component: dict[str, Any] = {"type": "library", "name": name}
    if version is not None:
        component["version"] = version
    component.update(extra)
    return component


def sbom(components: list[dict[str, Any]], *, spec: str = "1.5") -> str:
    document: dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": spec, "version": 1}
    document["components"] = components
    return json.dumps(document)


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def nested(levels: int) -> dict[str, Any]:
    inner: dict[str, Any] | None = None
    for level in range(levels, 0, -1):
        component = lib(f"c{level}", "1")
        if inner is not None:
            component["components"] = [inner]
        inner = component
    assert inner is not None
    return inner


BASE_COMPONENTS = [lib("a", "1.0")]

SCENARIOS: dict[str, list[dict[str, Any]]] = {
    "added": [lib("a", "1.0"), lib("b", "1.0")],
    "removed": [],
    "upgrade": [lib("a", "2.0")],
    "downgrade": [lib("a", "0.5")],
    "changed": [lib("a", "abc")],
    "license": [lib("a", "1.0", licenses=[{"license": {"id": "MIT"}}])],
}

PAIRS = [(scenario, category) for scenario in SCENARIOS for category in SCENARIOS]


def run_with_head(tmp_path: Path, head: Path | str) -> int:
    base = write(tmp_path / "base.json", sbom(BASE_COMPONENTS))
    head_path = head if isinstance(head, Path) else write(tmp_path / "head.json", head)
    return main([str(base), str(head_path)])


def test_text_report_and_default_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    code = main([str(FIXTURES / "base.json"), str(FIXTURES / "head.json")])
    assert code == 0
    output = capsys.readouterr().out
    assert "Added (1)\n  + pkg:pypi/requests-x 1\n" in output
    assert output.endswith("  ! pkg:npm/lic MIT -> Apache-2.0 OR MIT\n")


def test_format_json_output_equals_the_golden_file(capsys: pytest.CaptureFixture[str]) -> None:
    """'--format json' output equals a byte-exact golden ordered by key."""
    base = str(FIXTURES / "base.json")
    head = str(FIXTURES / "head.json")
    assert main([base, head, "--format", "json"]) == 0
    golden = (FIXTURES / "expected.json").read_text(encoding="utf-8")
    assert capsys.readouterr().out == golden


@pytest.mark.parametrize(("scenario", "category"), PAIRS)
def test_fail_on_single_category(tmp_path: Path, scenario: str, category: str) -> None:
    base = write(tmp_path / "base.json", sbom(BASE_COMPONENTS))
    head = write(tmp_path / "head.json", sbom(SCENARIOS[scenario]))
    expected = 1 if scenario == category else 0
    assert main([str(base), str(head), "--fail-on", category]) == expected


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("added", 1),
        ("downgrade", 1),
        ("upgrade", 0),
        ("removed", 0),
        ("changed", 0),
        ("license", 0),
    ],
)
def test_fail_on_added_and_downgrade(tmp_path: Path, scenario: str, expected: int) -> None:
    base = write(tmp_path / "base.json", sbom(BASE_COMPONENTS))
    head = write(tmp_path / "head.json", sbom(SCENARIOS[scenario]))
    assert main([str(base), str(head), "--fail-on", "added,downgrade"]) == expected


def test_fail_on_tolerates_spaces_and_lists(tmp_path: Path) -> None:
    base = write(tmp_path / "base.json", sbom(BASE_COMPONENTS))
    head = write(tmp_path / "head.json", sbom(SCENARIOS["removed"]))
    assert main([str(base), str(head), "--fail-on", "added, removed"]) == 1


def test_without_fail_on_changes_do_not_fail(tmp_path: Path) -> None:
    assert run_with_head(tmp_path, sbom(SCENARIOS["downgrade"])) == 0


@pytest.mark.parametrize("value", ["bogus", "added,bogus", "", "added,", "ADDED"])
def test_unknown_fail_on_category_exits_2(tmp_path: Path, value: str) -> None:
    base = write(tmp_path / "base.json", sbom(BASE_COMPONENTS))
    assert main([str(base), str(base), "--fail-on", value]) == 2


def test_unknown_category_is_explained(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = write(tmp_path / "base.json", sbom(BASE_COMPONENTS))
    assert main([str(base), str(base), "--fail-on", "bogus"]) == 2
    assert "unknown category" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["only-one.json"],
        ["a.json", "b.json", "--format", "xml"],
        ["a.json", "b.json", "--nope"],
    ],
)
def test_bad_flags_exit_2(argv: list[str]) -> None:
    assert main(argv) == 2


def test_help_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == 0
    assert "usage: sbom-diff" in capsys.readouterr().out


def test_spdx_document_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    head = json.dumps({"bomFormat": "SPDX", "specVersion": "2.3"})
    assert run_with_head(tmp_path, head) == 2
    captured = capsys.readouterr()
    assert "(format)" in captured.err
    assert captured.out == ""


def test_spec_version_1_3_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_with_head(tmp_path, sbom([], spec="1.3")) == 2
    assert "(unsupported_version)" in capsys.readouterr().err


def test_52_428_801_byte_file_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    big = tmp_path / "big.json"
    big.write_bytes(b" " * 52_428_801)
    assert run_with_head(tmp_path, big) == 2
    assert "(too_large)" in capsys.readouterr().err


def test_100_001_components_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_with_head(tmp_path, sbom([lib("c")] * 100_001)) == 2
    assert "(too_large)" in capsys.readouterr().err


def test_33_levels_of_nesting_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_with_head(tmp_path, sbom([nested(33)])) == 2
    assert "(too_deep)" in capsys.readouterr().err


def test_invalid_json_and_missing_files_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_with_head(tmp_path, "{not json") == 2
    assert "(invalid_json)" in capsys.readouterr().err
    assert run_with_head(tmp_path, tmp_path / "missing.json") == 2
    assert "(format)" in capsys.readouterr().err


def test_invalid_base_exits_2(tmp_path: Path) -> None:
    base = write(tmp_path / "base.json", "[]")
    head = write(tmp_path / "head.json", sbom(BASE_COMPONENTS))
    assert main([str(base), str(head)]) == 2


def test_python_dash_m_entry_point(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    base = write(tmp_path / "base.json", sbom(BASE_COMPONENTS))
    monkeypatch.setattr(sys, "argv", ["sbom-diff", str(base), str(base)])
    monkeypatch.delitem(sys.modules, "sbom_diff.__main__", raising=False)
    with pytest.raises(SystemExit) as info:
        runpy.run_module("sbom_diff", run_name="__main__")
    assert info.value.code == 0
    assert "No differences." in capsys.readouterr().out

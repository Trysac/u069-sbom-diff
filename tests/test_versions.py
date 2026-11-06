"""Tests for compare_versions."""

from __future__ import annotations

import itertools

import pytest

from sbom_diff import SbomDiffError, compare_versions

CASES: list[tuple[str, str, int | None]] = [
    ("1.2.10", "1.2.9", 1),
    ("2.0.0", "2.1.0", -1),
    ("v1.2", "1.2.0", 0),
    ("1.0.0-rc.1", "1.0.0", -1),
    ("1.0.0-alpha.2", "1.0.0-alpha.10", -1),
    ("1.0.0+b1", "1.0.0", 0),
    ("abc123", "def", None),
    ("1.0.0", "1.0.0-rc.1", 1),
    ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ("1.0.0-alpha.1", "1.0.0-alpha", 1),
    ("1.0.0-1", "1.0.0-alpha", -1),
    ("1.0.0-alpha", "1.0.0-beta", -1),
    ("1.0.0-alpha-1", "1.0.0-alpha-2", -1),
    ("1.0.0-rc.1", "1.0.0-rc.1", 0),
    ("1.0.0-01", "1.0.0-1", 0),
    ("1.0.0-rc.1+build.5", "1.0.0-rc.1", 0),
    ("V1.0", "1.0", 0),
    ("1.0", "1.0.0.0", 0),
    (" 1.0 ", "1.0", 0),
    ("1.0.1", "1.0", 1),
    ("1..2", "1.2", None),
    ("1.0-", "1.0", None),
    ("1.0-a_b", "1.0", None),
    ("", "1.0", None),
    ("1.0", "", None),
    ("v", "1", None),
    ("1.\u00b2", "1.0", None),
]

ORDERED = [case for case in CASES if case[2] is not None]


@pytest.mark.parametrize(("left", "right", "expected"), CASES)
def test_compare_versions(left: str, right: str, expected: int | None) -> None:
    assert compare_versions(left, right) == expected


@pytest.mark.parametrize(("left", "right", "expected"), ORDERED)
def test_comparison_is_antisymmetric(left: str, right: str, expected: int) -> None:
    assert compare_versions(right, left) == -expected


def test_acceptance_examples() -> None:
    assert compare_versions("1.2.10", "1.2.9") == 1
    assert compare_versions("2.0.0", "2.1.0") == -1
    assert compare_versions("v1.2", "1.2.0") == 0
    assert compare_versions("1.0.0-rc.1", "1.0.0") == -1
    assert compare_versions("1.0.0-alpha.2", "1.0.0-alpha.10") == -1
    assert compare_versions("1.0.0+b1", "1.0.0") == 0
    assert compare_versions("abc123", "def") is None


def test_semver_precedence_chain() -> None:
    chain = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ]
    for lower, higher in itertools.pairwise(chain):
        assert compare_versions(lower, higher) == -1


def test_overlong_versions_are_rejected() -> None:
    assert compare_versions("1" * 256, "1") == 1
    with pytest.raises(SbomDiffError) as left_info:
        compare_versions("1" * 257, "1")
    assert left_info.value.code == "too_large"
    with pytest.raises(SbomDiffError) as right_info:
        compare_versions("1", "1" * 257)
    assert right_info.value.code == "too_large"

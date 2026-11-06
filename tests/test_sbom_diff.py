"""Behavior tests for the public API of sbom_diff."""

from __future__ import annotations

import pytest

import sbom_diff


def test_normalize_trims_and_lowercases() -> None:
    assert sbom_diff.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        sbom_diff.normalize(value)


def test_version_is_semver() -> None:
    parts = sbom_diff.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)

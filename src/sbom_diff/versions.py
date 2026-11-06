"""Version comparison following SemVer 2.0.0 precedence rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sbom_diff.errors import SbomDiffError

MAX_VERSION_LENGTH = 256

_IDENTIFIER = re.compile(r"[0-9A-Za-z-]+")

_PreKey = tuple[tuple[int, int, str], ...]


@dataclass(frozen=True)
class _Parsed:
    release: tuple[int, ...]
    pre: _PreKey


def _identifier_key(identifier: str) -> tuple[int, int, str]:
    """Numeric identifiers sort below alphanumeric ones and compare as numbers."""
    if identifier.isdigit():
        return (0, int(identifier), "")
    return (1, 0, identifier)


def _parse(text: str) -> _Parsed | None:
    if len(text) > MAX_VERSION_LENGTH:
        raise SbomDiffError(
            "too_large",
            f"version is longer than {MAX_VERSION_LENGTH} characters",
        )
    value = text.strip()
    if value[:1] in ("v", "V"):
        value = value[1:]
    value = value.split("+", 1)[0]
    release, separator, pre = value.partition("-")
    segments = release.split(".")
    if not all(part.isascii() and part.isdigit() for part in segments):
        return None
    numbers = tuple(int(part) for part in segments)
    if not separator:
        return _Parsed(numbers, ())
    identifiers = pre.split(".")
    if not all(_IDENTIFIER.fullmatch(part) for part in identifiers):
        return None
    return _Parsed(numbers, tuple(_identifier_key(part) for part in identifiers))


def _sign(left: tuple[Any, ...], right: tuple[Any, ...]) -> int:
    if left < right:
        return -1
    if left > right:
        return 1
    return 0


def _pad(values: tuple[int, ...], width: int) -> tuple[int, ...]:
    return values + tuple(0 for _ in range(width - len(values)))


def compare_versions(a: str, b: str) -> int | None:
    """Compare two version strings.

    A leading ``v`` and ``+build`` metadata are ignored. The release part must be dot-separated
    digits (trailing zeros are padded, so ``1.2`` equals ``1.2.0``); a release with a pre-release
    is lower than the same release without one, and pre-releases follow SemVer 2.0.0 section 11.

    Returns:
        -1, 0 or 1, or ``None`` when either version is not comparable.

    Raises:
        SbomDiffError: code ``too_large`` if a version is longer than 256 characters.
    """
    left = _parse(a)
    right = _parse(b)
    if left is None or right is None:
        return None
    width = max(len(left.release), len(right.release))
    result = _sign(_pad(left.release, width), _pad(right.release, width))
    if result != 0:
        return result
    if not left.pre and not right.pre:
        return 0
    if not left.pre:
        return 1
    if not right.pre:
        return -1
    return _sign(left.pre, right.pre)

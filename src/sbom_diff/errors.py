"""Typed errors raised by sbom_diff."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal["format", "unsupported_version", "too_large", "too_deep", "invalid_json"]

MAX_MESSAGE_LENGTH = 200


class SbomDiffError(Exception):
    """Base error of the library.

    Attributes:
        code: stable machine-readable error code.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        if len(message) > MAX_MESSAGE_LENGTH:
            limit = MAX_MESSAGE_LENGTH - 3
            message = message[:limit] + "..."
        super().__init__(message)
        self.code: ErrorCode = code


def quote(value: object, limit: int = 60) -> str:
    """Return a short, safe representation of ``value`` for use in messages."""
    if not isinstance(value, str):
        return f"<{type(value).__name__}>"
    suffix = "..." if len(value) > limit else ""
    return repr(value[:limit]) + suffix

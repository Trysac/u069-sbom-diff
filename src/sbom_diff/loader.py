"""Load CycloneDX JSON SBOMs into flat component lists."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from sbom_diff.errors import SbomDiffError, quote
from sbom_diff.models import Component
from sbom_diff.versions import MAX_VERSION_LENGTH

logger = logging.getLogger(__name__)

DEFAULT_MAX_BYTES = 52_428_800
MAX_COMPONENT_DEPTH = 32
MAX_COMPONENTS = 100_000
MAX_JSON_DEPTH = 128
SUPPORTED_SPEC_VERSIONS = ("1.4", "1.5", "1.6")

_TOKEN = re.compile("[" + re.escape('"[]{}') + "]")
_SEPARATORS = re.compile(r"[-_.]+")


def _string_end(text: str, start: int) -> int:
    """Return the index of the quote closing the string opened at ``start``, or -1."""
    position = start + 1
    while True:
        position = text.find('"', position)
        if position == -1:
            return -1
        backslashes = 0
        while text[position - 1 - backslashes] == "\\":
            backslashes += 1
        if backslashes % 2 == 0:
            return position
        position += 1


def _check_json_depth(text: str) -> None:
    """Reject excessive bracket nesting iteratively, before the JSON parser can recurse."""
    depth = 0
    position = 0
    while True:
        match = _TOKEN.search(text, position)
        if match is None:
            return
        index = match.start()
        char = text[index]
        if char == '"':
            end = _string_end(text, index)
            if end == -1:
                return
            position = end + 1
            continue
        position = index + 1
        if char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise SbomDiffError(
                    "too_deep",
                    f"JSON nesting exceeds {MAX_JSON_DEPTH} levels",
                )
        else:
            depth -= 1


def _parse_purl(purl: str) -> tuple[str, str] | None:
    """Return ``(key, version)`` for a package URL, or ``None`` when it is not usable."""
    text = purl.strip()
    if text[:4].lower() != "pkg:":
        return None
    rest = text[4:].split("#", 1)[0].split("?", 1)[0].lstrip("/")
    version = ""
    at = rest.find("@", rest.rfind("/") + 1)
    if at != -1:
        start = at + 1
        version = unquote(rest[start:])
        rest = rest[:at]
    segments = rest.split("/")
    if len(segments) < 2:
        return None
    purl_type = segments[0].strip().lower()
    name = unquote(segments[-1])
    if not purl_type or not name:
        return None
    if purl_type == "pypi":
        name = _SEPARATORS.sub("-", name).lower()
    namespace = "/".join(unquote(part) for part in segments[1:-1] if part)
    prefix = f"pkg:{purl_type}/"
    key = f"{prefix}{namespace}/{name}" if namespace else f"{prefix}{name}"
    return key, version


def _text_field(raw: dict[str, Any], field_name: str, *, required: bool = False) -> str:
    value: object = raw.get(field_name)
    if value is None:
        text = ""
    elif isinstance(value, str):
        text = value
    else:
        raise SbomDiffError("format", f"component field {field_name!r} must be a string")
    if required and not text:
        raise SbomDiffError("format", f"component field {field_name!r} is required")
    return text


def _licenses(raw: dict[str, Any]) -> tuple[str, ...]:
    items: object = raw.get("licenses")
    if items is None:
        return ()
    if not isinstance(items, list):
        raise SbomDiffError("format", "component licenses must be an array")
    found: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise SbomDiffError("format", "license entries must be objects")
        value: object = None
        entry = item.get("license")
        if isinstance(entry, dict):
            value = entry.get("id") or entry.get("name")
        if not value:
            value = item.get("expression")
        if isinstance(value, str) and value:
            found.add(value)
    return tuple(sorted(found))


def _build_component(raw: dict[str, Any]) -> Component:
    name = _text_field(raw, "name", required=True)
    group = _text_field(raw, "group")
    version = _text_field(raw, "version")
    purl = _text_field(raw, "purl")
    parsed = _parse_purl(purl) if purl else None
    if parsed is None:
        key = f"{group}/{name}" if group else name
    else:
        key = parsed[0]
        version = version or parsed[1]
    if len(version) > MAX_VERSION_LENGTH:
        raise SbomDiffError(
            "too_large",
            f"component version exceeds {MAX_VERSION_LENGTH} characters",
        )
    return Component(key, name, group, version, purl, _licenses(raw))


def _collect(top: list[Any]) -> list[Component]:
    """Flatten components and nested components iteratively, in document order."""
    result: list[Component] = []
    stack: list[tuple[object, int]] = [(item, 1) for item in reversed(top)]
    while stack:
        raw, level = stack.pop()
        if level > MAX_COMPONENT_DEPTH:
            raise SbomDiffError(
                "too_deep",
                f"components are nested deeper than {MAX_COMPONENT_DEPTH} levels",
            )
        if not isinstance(raw, dict):
            raise SbomDiffError("format", "every component must be an object")
        if len(result) >= MAX_COMPONENTS:
            raise SbomDiffError("too_large", f"more than {MAX_COMPONENTS} components")
        result.append(_build_component(raw))
        children = raw.get("components")
        if children is None:
            continue
        if not isinstance(children, list):
            raise SbomDiffError("format", "nested components must be an array")
        stack.extend((child, level + 1) for child in reversed(children))
    return result


def _parse_document(document: object) -> list[Component]:
    if not isinstance(document, dict):
        raise SbomDiffError("format", "SBOM must be a JSON object")
    bom_format = document.get("bomFormat")
    if bom_format != "CycloneDX":
        raise SbomDiffError(
            "format",
            f"bomFormat must be 'CycloneDX', got {quote(bom_format)}",
        )
    spec_version = document.get("specVersion")
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise SbomDiffError(
            "unsupported_version",
            f"unsupported specVersion {quote(spec_version)}; supported: 1.4, 1.5, 1.6",
        )
    top = document.get("components")
    if top is None:
        return []
    if not isinstance(top, list):
        raise SbomDiffError("format", "components must be an array")
    return _collect(top)


def _read_path(path: Path, max_bytes: int) -> str:
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise SbomDiffError("format", "cannot read SBOM file") from exc
    if len(data) > max_bytes:
        raise SbomDiffError("too_large", f"SBOM file is larger than {max_bytes} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise SbomDiffError("invalid_json", "SBOM file is not valid UTF-8") from None


def _read_text(text: str, max_bytes: int) -> str:
    if len(text) > max_bytes or len(text.encode("utf-8", "surrogatepass")) > max_bytes:
        raise SbomDiffError("too_large", f"SBOM text is larger than {max_bytes} bytes")
    return text


def _read_source(source: Path | str, max_bytes: int) -> str:
    if isinstance(source, Path):
        return _read_path(source, max_bytes)
    return _read_text(source, max_bytes)


def load_sbom(source: Path | str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> list[Component]:
    """Load a CycloneDX 1.4-1.6 JSON SBOM and return its flattened components.

    Args:
        source: a ``Path`` to read, or a ``str`` holding the JSON text.
        max_bytes: maximum size of the document in bytes (checked before parsing).

    Components and nested components are flattened (at most 32 levels and 100,000 components);
    ``metadata.component`` is the subject of the SBOM and is never returned.

    Raises:
        SbomDiffError: ``format``, ``unsupported_version``, ``too_large``, ``too_deep`` or
            ``invalid_json``.
        ValueError: if ``max_bytes`` is smaller than 1.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    text = _read_source(source, max_bytes)
    _check_json_depth(text)
    try:
        document = json.loads(text.removeprefix("\ufeff"))
    except RecursionError:
        raise SbomDiffError("too_deep", "JSON nesting is too deep to parse") from None
    except ValueError:
        raise SbomDiffError("invalid_json", "document is not valid JSON") from None
    components = _parse_document(document)
    logger.debug("loaded %d components", len(components))
    return components

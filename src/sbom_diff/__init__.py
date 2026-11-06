"""Compare two CycloneDX 1.4-1.6 JSON SBOMs and report what changed."""

from __future__ import annotations

import logging

from sbom_diff.differ import diff
from sbom_diff.errors import SbomDiffError
from sbom_diff.loader import load_sbom
from sbom_diff.models import (
    Component,
    ComponentEntry,
    LicenseChange,
    SbomDiff,
    VersionChange,
)
from sbom_diff.report import render
from sbom_diff.versions import compare_versions

__all__ = [
    "Component",
    "ComponentEntry",
    "LicenseChange",
    "SbomDiff",
    "SbomDiffError",
    "VersionChange",
    "__version__",
    "compare_versions",
    "diff",
    "load_sbom",
    "render",
]

__version__ = "0.1.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())

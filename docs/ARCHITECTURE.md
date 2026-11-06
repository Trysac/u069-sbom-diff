# Architecture

## Purpose

`trysac-sbom-diff` is a small, dependency-free Python library (import name `sbom_diff`, stdlib only) that compares two CycloneDX 1.4-1.6 JSON SBOMs and reports added, removed, upgraded, downgraded and changed components and license changes, keyed by normalised purl.

## Shape

```text
caller code --> sbom_diff (public API in __init__.py)
                    |
                    +-- loader.py   (read, limit, parse, flatten)
                    +-- differ.py   (index and compare by key)
                    +-- versions.py (SemVer 2.0.0 comparison)
                    +-- report.py   (text and JSON rendering)
                    +-- __main__.py (CLI: exit codes 0, 1, 2)
```

- **Public API**: the names listed in `__all__` of `src/sbom_diff/__init__.py`: `Component`, `ComponentEntry`, `LicenseChange`, `SbomDiff`, `SbomDiffError`, `VersionChange`, `__version__`, `compare_versions`, `diff`, `load_sbom`, `render`.
- **Errors**: invalid input raises `SbomDiffError` with a stable `code`; `render` and `load_sbom` raise `ValueError` for invalid arguments.
- **Logging**: a module logger with a `NullHandler`; the library never configures logging.
- **Side effects**: `load_sbom` reads a file only when given a `Path`. The CLI is the only code that prints or exits.

## Quality contract

The gates are described in [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.

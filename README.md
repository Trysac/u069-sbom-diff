# sbom-diff

[![PyPI version](https://img.shields.io/pypi/v/trysac-sbom-diff)](https://pypi.org/project/trysac-sbom-diff/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-sbom-diff)](LICENSE)
[![CI](https://github.com/Trysac/u069-sbom-diff/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u069-sbom-diff/actions/workflows/ci.yml)

Compare two CycloneDX 1.4-1.6 JSON SBOMs: added, removed, upgraded, downgraded components and license changes keyed by normalised purl, with CI exit codes

## Problem

When a release rebuilds its dependency tree, reviewers cannot tell from a lockfile diff which
components were added, removed or downgraded, or whose license changed. CycloneDX SBOMs carry that
data but are large nested JSON. `sbom-diff` turns two SBOMs into a reviewable report and a CI exit
code, without needing the .NET `cyclonedx-cli`.

## Install

```sh
pip install trysac-sbom-diff
# or
uv add trysac-sbom-diff
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
from pathlib import Path

from sbom_diff import diff, load_sbom, render

result = diff(load_sbom(Path("base.json")), load_sbom(Path("head.json")))
print(render(result, "text"))
```

Public API: `load_sbom(source, *, max_bytes=52_428_800)` reads a `Path` or JSON text and returns flattened components (raises `SbomDiffError` on invalid input; `ValueError` if `max_bytes` < 1); `diff(base, head)` returns `SbomDiff` with `added`, `removed` (lists of `ComponentEntry`), `changed` (`VersionChange` with kind `upgrade`, `downgrade` or `changed`) and `license_changes` (`LicenseChange`), every list sorted by key; `render(result, fmt)` formats the result as `'text'` or `'json'` (sorted keys, indent 2); `compare_versions(a, b)` returns -1, 0, 1 or `None` when a version is not comparable (SemVer 2.0.0 precedence, leading `v` and `+build` ignored).

Limits: 50 MiB per document, 32 nesting levels for components, 100,000 components, 128 JSON bracket levels, 256 characters per version, 200 characters per error message. Only `bomFormat` `CycloneDX` with `specVersion` 1.4, 1.5 or 1.6 is accepted. `metadata.component` is never compared.

Keys follow the package-url specification (qualifiers and subpath dropped; PEP 503 normalisation for `pypi`). Components without purl are keyed `group/name` or `name`.

Errors: `SbomDiffError.code` is one of `format`, `unsupported_version`, `too_large`, `too_deep`, `invalid_json`. An unreadable file is reported as `format`.

### Command line

```sh
sbom-diff base.json head.json --format json --fail-on added,downgrade
```

`--format` is `text` (default) or `json`. `--fail-on` takes a comma list of `added`, `removed`,
`upgrade`, `downgrade`, `changed`, `license`.

Exit codes:

- `0`: no failing category is present
- `1`: at least one `--fail-on` category is non-empty
- `2`: invalid input or flags (bad format, unsupported version, too large, too deep, unknown category)

## Why not cyclonedx-cli?

`cyclonedx-cli` is a .NET binary; `sbom-diff` is a stdlib-only Python package that runs anywhere the Python environment runs.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and limits.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez

# sbom-diff

[![PyPI version](https://img.shields.io/pypi/v/trysac-sbom-diff)](https://pypi.org/project/trysac-sbom-diff/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-sbom-diff)](LICENSE)
[![CI](https://github.com/Trysac/u069-sbom-diff/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u069-sbom-diff/actions/workflows/ci.yml)

Compare two CycloneDX 1.4-1.6 JSON SBOMs: added, removed, upgraded, downgraded components and license changes keyed by normalised purl, with CI exit codes

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-sbom-diff
# or
uv add trysac-sbom-diff
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import sbom_diff

# normalize() trims surrounding whitespace and lower-cases the text.
print(sbom_diff.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    sbom_diff.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez

"""Command line interface: ``python -m sbom_diff``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sbom_diff.differ import diff
from sbom_diff.errors import SbomDiffError, quote
from sbom_diff.loader import load_sbom
from sbom_diff.models import CATEGORIES
from sbom_diff.report import render


def _categories(value: str) -> tuple[str, ...]:
    names = tuple(part.strip() for part in value.split(","))
    for name in names:
        if name not in CATEGORIES:
            raise argparse.ArgumentTypeError(f"unknown category {quote(name)}")
    return names


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom-diff",
        description="Compare two CycloneDX 1.4-1.6 JSON SBOMs.",
    )
    parser.add_argument("base", help="path of the base SBOM (JSON)")
    parser.add_argument("head", help="path of the head SBOM (JSON)")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format",
    )
    parser.add_argument(
        "--fail-on",
        type=_categories,
        default=(),
        metavar="CATEGORIES",
        help="comma list of " + ", ".join(CATEGORIES) + "; exit 1 when one of them is non-empty",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return the exit code: 0 ok, 1 failing category, 2 invalid input or flags."""
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        result = diff(load_sbom(Path(args.base)), load_sbom(Path(args.head)))
    except SbomDiffError as exc:
        print(f"sbom-diff: error ({exc.code}): {exc}", file=sys.stderr)
        return 2
    print(render(result, args.format))
    counts = result.category_counts()
    return 1 if any(counts[name] for name in args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())

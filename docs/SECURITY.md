# Security notes

## Threat model

`trysac-sbom-diff` is a pure library with one read path: `load_sbom` reads a file when given a `Path`. It performs no network access and no subprocess calls.

Defended:

- **Oversized input**: the byte limit (default 52,428,800 bytes) is enforced by reading at most `max_bytes + 1` bytes before parsing; the same limit applies to text input.
- **Deep nesting**: JSON bracket depth is pre-scanned iteratively (limit 128) before `json.loads`, so `RecursionError` from deep JSON is avoided; nested components are walked iteratively with a limit of 32 levels.
- **Excess components**: at most 100,000 components are accepted.
- **Oversized versions**: versions longer than 256 characters are rejected with `too_large`.
- **Report forgery**: text output escapes non-printable characters so SBOM data cannot inject lines.
- **Error message size**: `SbomDiffError` messages are truncated to 200 characters.
- **Untrusted code**: no `eval`, `exec` or pickle; only `json.loads` is used.

Not defended:

- **Memory use within limits**: a 50 MiB document can still expand to a large in-memory structure; the library does not stream.
- **Unreadable files** are reported as code `format`, which does not distinguish permission errors from format errors.
- **Semantic trust**: the library reports what the SBOM declares; it does not verify signatures, hashes or whether declared licenses are correct.
- **Vulnerability status**: the library does not check components against vulnerability databases.

Supply chain: no runtime dependencies. Dependabot runs weekly and GitHub Actions are pinned to major versions.

Secrets: `gitleaks` runs in the local gates and in CI.

Publishing: releases use PyPI trusted publishing (OIDC) when available.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

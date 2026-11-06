# Compare CycloneDX SBOMs by normalised purl keys with a stdlib-only, limit-first loader

Status: accepted (generated, pending human review)

## Context

Reviewers cannot see from a lockfile diff which components were added, removed or downgraded, or whose license changed. CycloneDX SBOMs hold that data but are large nested JSON, and the existing cyclonedx-cli is a .NET binary. SBOMs are untrusted input, so loading must be bounded in size, nesting depth and component count, and must not rely on the recursive JSON parser to survive hostile nesting.

## Decision

Implement a Python 3.10+ standard-library-only package. Components are matched by a key derived from the package-url (type lowercased, namespace and name percent-decoded, version, qualifiers and subpath dropped, PEP 503 normalisation for pypi), falling back to group/name or name. A key with several versions on one side is a version set. Versions are compared with SemVer 2.0.0 precedence and incomparable versions yield the kind 'changed' rather than guessing ecosystem schemes. The loader checks the byte limit before parsing, scans bracket depth iteratively before json.loads, walks components with an explicit stack (depth 32, 100,000 components) and excludes metadata.component. All failures raise SbomDiffError with a stable code. The CLI maps results to exit codes 0, 1 and 2, and text output escapes control characters.

## Consequences

Diffs are deterministic, sorted by key and CI-friendly, and hostile documents fail fast with typed errors, with no dependencies to audit. Only CycloneDX JSON 1.4-1.6 is supported; SPDX, XML, protobuf, VEX, vulnerabilities and graph diffs are out of scope. PEP 440 or Maven version differences are reported as 'changed' instead of upgrade or downgrade. Version strings are capped at 256 characters, and the pre-parse depth scan costs a linear pass over the document.

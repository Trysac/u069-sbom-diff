# Project record

## Objective

Give reviewers and CI a focused report of what changed between two CycloneDX 1.4-1.6 JSON SBOMs: components added, removed, upgraded, downgraded or changed, and license changes, with exit codes for CI gating.

## Scope

- In scope: loading CycloneDX 1.4, 1.5 and 1.6 JSON documents; flattening components and nested components; purl-based keys (PEP 503 for pypi); SemVer 2.0.0 version comparison; text and JSON reports; a CLI with `--format` and `--fail-on`.
- Out of scope: SPDX documents, XML or protobuf formats, vulnerabilities, VEX, graph diffs, ecosystem version schemes other than SemVer-like (incomparable PEP 440 or Maven versions are reported as `changed`).

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 492729 / 118656 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.9465 |

## Factory run u069 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2276 | 105951 | 0 | 4246 | 0.5325 |
| fix-1 | claude-sonnet-5-5 | no | 4 | 481 | 5885 | 24523 | 0.0220 |
| fix-2 | claude-sonnet-5-5 | no | 6 | 434 | 8756 | 43844 | 0.0306 |
| fix-3 | claude-sonnet-5-5 | no | 6 | 411 | 6762 | 41366 | 0.0252 |
| fix-4 | claude-sonnet-5-5 | no | 6 | 448 | 7249 | 42341 | 0.0268 |
| fix-1 | claude-sonnet-5-5 | no | 8 | 771 | 7036 | 55963 | 0.0309 |
| audit | claude-sonnet-5-5 | no | 12 | 4571 | 45725 | 119113 | 0.1720 |
| fix-2 | claude-sonnet-5-5 | no | 6 | 1414 | 7403 | 40197 | 0.0367 |
| docs | claude-haiku-5-5 | no | 118812 | 4175 | 0 | 0 | 0.0698 |

Total: $0.9465. Prices: Anthropic list prices.

# Testing

## Running

```sh
uv run pytest --cov=sbom_diff   # tests with coverage report
uv run python scripts/check.py      # every gate, as CI and the factory run it
```

## Policy

- Branch coverage of `src/sbom_diff` must stay at or above 80 %; the gate fails below it.
- Tests exercise the public API (`import sbom_diff`) and assert return values, raised exceptions and their codes and messages.
- Each bug fix starts with a failing test that reproduces it.
- Tests are deterministic: no network, no wall clock, no dependence on test order.

## Layout

`tests/test_<module>.py` mirrors each public module. Fixture SBOMs live under `tests/fixtures`.

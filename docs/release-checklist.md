# Release Checklist

`pkgwhy` releases are validated locally before any push, tag, publication, or repository-visibility change.

This checklist is required before any release candidate or final release is described as locally ready. Passing it does not publish anything and does not prove packages are safe.

## Scope Review

- Confirm the target version and milestone in `CHANGELOG.md`, `README.md`, `SECURITY.md`, and `pyproject.toml`.
- Confirm future-only features are labelled future, planned, experimental, or not included in the release.
- Confirm no production-ready, definitive malware-detection, or full-sandboxing claims are present.
- Confirm dynamic analysis is either implemented and tested as an opt-in sandbox backend or clearly labelled experimental for the release line.
- Confirm vulnerability, provenance, attestation, and trusted-publishing fields remain source-attributed, `unknown`, `unavailable`, or `not_implemented` when evidence is unavailable.

## Local Checks

Run:

```bash
git status
.venv/bin/python -m pytest
git diff --check
```

Run CLI smokes:

```bash
.venv/bin/python -m pkgwhy --help
.venv/bin/python -m pkgwhy scan
.venv/bin/python -m pkgwhy explain typer
.venv/bin/python -m pkgwhy inspect typer
.venv/bin/python -m pkgwhy judge typer --json
.venv/bin/python -m pkgwhy risk typer
.venv/bin/python -m pkgwhy audit --limit 2 --json
.venv/bin/python -m pkgwhy precheck typer --json
.venv/bin/python -m pkgwhy precheck -r tests/fixtures/precheck/requirements.txt --json
.venv/bin/python -m pkgwhy precheck pyproject.toml --json
.venv/bin/python -m pkgwhy pip --help
.venv/bin/python -m pkgwhy pip install --help
.venv/bin/python -m pkgwhy pip install typer --dry-run --json
.venv/bin/python -m pkgwhy typos requests pandas-stubs
.venv/bin/python -m pkgwhy agent --help
.venv/bin/python -m pkgwhy agent precheck typer --json
.venv/bin/python -m pkgwhy dynamic --help
.venv/bin/python -m pkgwhy dynamic inspect --help
```

These default smokes are expected to work offline. Optional online release checks, such as explicit OSV.dev or PyPI provenance lookups, should run only when online checks are in scope for the release pass and failures can be reported as lookup unavailability rather than safety evidence.

Run release artifact checks:

```bash
rm -rf dist build *.egg-info
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
```

## Public Trace Scan

Tracked public files should not contain private workflow files or provider-attribution traces. Run:

```bash
python scripts/check_public_traces.py
```

Expected result: `public trace scan passed`.

After building artifacts, also run:

```bash
python scripts/check_public_traces.py dist/*
```

Product-facing `pkgwhy agent` references are allowed.

## Review Gate

- Commit coherent local work before external review.
- Run external review only after local checks pass and the diff is coherent.
- Fix accepted findings only.
- Defer or reject findings that weaken safety boundaries, loosen hash/path/signature controls, run unknown code, remove conservative warnings, or overclaim security.
- Review results should be recorded exactly as returned. If external review is unavailable, report it as unavailable.

## Publishing Gate

Publication, tags, pushes, pull requests, visibility changes, cloud setup, billing setup, and credential setup are handled through the project release process, not ordinary local validation.

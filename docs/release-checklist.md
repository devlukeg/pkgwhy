# Release Checklist

`pkgwhy` releases are local-first until Luke explicitly approves pushing, tagging, publishing, or changing repository visibility.

This checklist is required before any release candidate is described as locally ready. Passing it does not publish anything and does not prove packages are safe.

## Scope Review

- Confirm the target version and milestone in `CHANGELOG.md`, `README.md`, `SECURITY.md`, and `pyproject.toml`.
- Confirm future-only features are labelled future, planned, experimental, or out of scope.
- Confirm no production-ready, definitive malware-detection, or full-sandboxing claims are present.
- Confirm dynamic analysis is either implemented and tested as an opt-in sandbox backend or explicitly experimental/out of scope for the release line.
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
.venv/bin/python -m pkgwhy typos requests pandas-stubs
.venv/bin/python -m pkgwhy agent --help
.venv/bin/python -m pkgwhy agent precheck typer --json
.venv/bin/python -m pkgwhy dynamic --help
.venv/bin/python -m pkgwhy dynamic inspect --help
```

Run release artifact checks:

```bash
rm -rf dist build *.egg-info
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
```

## Public Trace Scan

Tracked public files must not contain local work-loop files or provider traces. Run:

```bash
python scripts/check_public_traces.py
```

Expected result: `public trace scan passed`.

Product-facing `pkgwhy agent` references are allowed.

## Review Gate

- Commit coherent local work before external review.
- Run external review only after local checks pass and the diff is coherent.
- Fix accepted findings only.
- Defer or reject findings that weaken safety boundaries, loosen hash/path/signature controls, run unknown code, remove conservative warnings, or overclaim security.
- Do not fake review results.

## Publishing Gate

Do not run publish, tag, push, PR, visibility, cloud, billing, or credential setup commands unless Luke explicitly approves that action for the session.

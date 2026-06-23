# Contributing

`pkgwhy` is owned and maintained by Luke Gerakiteys. The project is in pre-alpha, so contributions should stay small, focused, and conservative.

## Development Setup

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest
```

## Engineering Rules

- Do not import or execute inspected package code during inspection.
- Keep inspection paths separate from the explicit `pkgwhy run` execution path for local private tools.
- Prefer static metadata, file, text, and AST analysis.
- Use conservative security language.
- Do not claim malware certainty without definitive evidence.
- Do not claim full sandboxing unless it is implemented.
- Do not fabricate metadata, source availability, vulnerability findings, risk results, signatures, hashes, or review findings.
- Keep JSON output stable for agent workflows.
- Keep PyPI/TestPyPI publishing, release tags, repository visibility changes, and pushes approval-gated.

## Before Submitting Changes

Run:

```bash
.venv/bin/python -m pytest
git diff --check
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
```

Do not add publishing automation, external services, payment processing, secrets, or cloud backends without explicit maintainer approval.

Repository: <https://github.com/devlukeg/pkgwhy>

Issues: <https://github.com/devlukeg/pkgwhy/issues>

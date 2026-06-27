# Contributing

`pkgwhy` is in release-candidate review for `1.0.0rc1`. Small, focused issues and pull requests are easiest to review right now.

## Development Setup

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest
```

## Engineering Rules

- Do not import or execute inspected package code during inspection.
- Keep inspection paths separate from the explicit `pkgwhy run` execution path for local private tools.
- Keep agent policy decisions separate from package inspection and local tool execution.
- Prefer static metadata, file, text, and AST analysis.
- Use conservative security language.
- Do not claim malware certainty without definitive evidence.
- Do not claim full sandboxing unless it is implemented.
- Do not fabricate metadata, source availability, vulnerability findings, risk results, signatures, hashes, or review findings.
- Keep JSON output stable for agent workflows.
- Keep release, publishing, repository visibility, and distribution changes out of ordinary feature pull requests.

## Before Submitting Changes

Run:

```bash
.venv/bin/python -m pytest
git diff --check
.venv/bin/python -m pkgwhy --help
.venv/bin/python -m pkgwhy agent policy --help
.venv/bin/python -m pkgwhy registry --help
.venv/bin/python -m pkgwhy run --help
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
```

For release-candidate work, also follow [docs/release-checklist.md](docs/release-checklist.md), [docs/versioning-policy.md](docs/versioning-policy.md), and [docs/production-readiness.md](docs/production-readiness.md).

Publishing automation, external services, payment processing, secrets, and cloud backends are out of scope for this candidate.

Repository: <https://github.com/devlukeg/pkgwhy>

Issues: <https://github.com/devlukeg/pkgwhy/issues>

# Contributing

`pkgwhy` is in the 1.0.0 release line. Small, focused issues and pull requests are easiest to review.

## Development Setup

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest
```

## Engineering Expectations

- Inspection code should read metadata, package files, text, and AST without importing or executing inspected package code.
- Keep inspection paths separate from the explicit `pkgwhy run` execution path for local private tools.
- Keep agent policy decisions separate from package inspection and local tool execution.
- Prefer static metadata, file, text, and AST analysis.
- Use conservative security language.
- Malware, source availability, vulnerability, risk, signature, hash, and review claims should be backed by evidence from the implementation or the cited source.
- Full sandboxing should be described only for isolation that is actually implemented and tested.
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

For release work, also follow [docs/release-checklist.md](docs/release-checklist.md), [docs/versioning-policy.md](docs/versioning-policy.md), and [docs/production-readiness.md](docs/production-readiness.md).

Publishing automation, external services, payment processing, secrets, and cloud backends are not included in this release line.

Repository: <https://github.com/devlukeg/pkgwhy>

Issues: <https://github.com/devlukeg/pkgwhy/issues>

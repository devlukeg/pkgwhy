# pkgwhy

Know why a package exists before you or your agent trusts it.

`pkgwhy` is an offline-first Python package intelligence CLI owned and maintained by Luke Gerakiteys. It explains installed packages, inspects local package files without importing them, reports conservative static security signals, and produces agent-readable JSON judgements.

## Status

`pkgwhy` is a **pre-alpha developer preview**. It is useful for local package inspection experiments, agent decision-support prototypes, and feedback on the CLI shape.

It is not a production security scanner, not malware-detection certainty, and not a sandbox. Results are evidence and signals for review, not proof that a package is safe or malicious.

Current version candidate: `0.1.0a0`.

## What Works Now

The current preview focuses on installed package intelligence:

```bash
pkgwhy scan
pkgwhy explain typer
pkgwhy why typer
pkgwhy inspect typer
pkgwhy judge typer --json
```

Implemented capabilities include:

- Installed distribution metadata using `importlib.metadata`.
- Package explanation from local knowledge and installed metadata.
- Direct, transitive, imported, unknown, and not-installed dependency status.
- Installed package size and largest-file reporting.
- Source availability and coarse readability signals.
- Native compiled file, JavaScript asset, package-manager, and CLI-entrypoint signals from file metadata.
- AST-only Python source scanning for filesystem, network, subprocess, environment, credential-pattern, dynamic-code, deserialisation, and encoded-payload signals.
- Conservative risk level, decision, warning, recommendation, evidence, and confidence output.
- Stable JSON output for agent workflows.

## What Is Not Implemented Yet

These are roadmap items, not current features:

- Typosquatting detection.
- JavaScript minification and obfuscation heuristics beyond basic file signals.
- Optional PyPI/source lookup and cache.
- Vulnerability database integration.
- Local private registry.
- `publish`, `pull`, `run`, and `tool judge`.
- Cloud/model-backed review.
- Billing, API keys, team plans, or enterprise deployment.
- OS-level sandboxing or container isolation.
- Production security-tool guarantees.

## Install

For local development from this repository:

```bash
python -m pip install -e ".[dev]"
pkgwhy --help
```

Install directly from GitHub:

```bash
python -m pip install "pkgwhy @ git+https://github.com/devlukeg/pkgwhy.git"
```

Future PyPI pre-alpha install command, after Luke explicitly approves publishing:

```bash
python -m pip install pkgwhy
```

## Quickstart

Inspect an installed package:

```bash
pkgwhy inspect typer
```

Explain why it may be present:

```bash
pkgwhy why typer
```

Emit machine-readable judgement JSON:

```bash
pkgwhy judge typer --json
```

Abbreviated JSON contract shape:

```json
{
  "schema_version": "pkgwhy.package_judgement.v1",
  "package": "package-name",
  "version": "installed-version-or-null",
  "decision": "allow | allow_with_caution | review_manually | sandbox_only | block",
  "risk_level": "low | medium | high | critical | unknown",
  "confidence": "low | medium | high",
  "summary": "summary from installed metadata or local explanation sources",
  "source_availability": "installed_source_present | installed_metadata_only | source_availability_unknown | not_installed",
  "installed_size_bytes": 0,
  "detected_capabilities": [],
  "warnings": [],
  "recommendation": "conservative recommendation text",
  "evidence": [],
  "capability_exposure_note": "Python packages run with the same permissions as the Python process. This analysis detects capabilities used or referenced by package code and metadata; static signals are not proof of runtime behavior or intent."
}
```

Run `pkgwhy judge <installed-package> --json` locally for real environment-specific values.

## Security Model

`pkgwhy` is static and metadata-first. It must not import or execute inspected packages merely to inspect them.

Python packages do not have browser or mobile style permissions. They usually run with the same operating-system permissions as the Python process and user executing them. `pkgwhy` therefore reports capability exposure signals, not guaranteed permissions.

Examples of static signals:

- A source file references `subprocess.run`.
- A package declares console scripts.
- Installed files include native compiled extensions.
- AST parsing finds `eval`, `exec`, `pickle.loads`, or environment-variable access.

These signals can be legitimate. They are review prompts, not proof of malicious behavior.

## Risk And Agent Decisions

Risk levels:

- `low`
- `medium`
- `high`
- `critical`
- `unknown`

Agent decisions:

- `allow`
- `allow_with_caution`
- `review_manually`
- `sandbox_only`
- `block`

The current risk engine is deliberately conservative and early. Treat it as decision support for humans and agents, not a final verdict.

## Private Registry Roadmap

`pkgwhy` is intended to grow into a private, security-aware executable layer for Python tools and AI-agent skills:

```bash
pkgwhy registry init ~/.pkgwhy/registry
pkgwhy publish ./my_tool.py
pkgwhy pull luke/my-tool
pkgwhy run luke/my-tool
pkgwhy tool judge luke/my-tool --json
```

The first runner design will use Python virtual environments for dependency isolation. A virtual environment is not a full operating-system sandbox, and `pkgwhy` will state that clearly when runner features are implemented.

## Future Cloud Review

The local/free product will remain offline-first: metadata inspection, AST scanning, capability signals, local risk rules, and local JSON judgement.

A future paid cloud/model-backed review layer may add deeper review over retrieved package evidence, review IDs, cached results, richer policy decisions, usage logs, privacy controls, and enterprise/private deployment options. Billing and cloud review are not implemented in this preview.

## Development

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
```

## Roadmap

1. Public pre-alpha packaging and documentation.
2. JavaScript readability and obfuscation heuristics.
3. Native/binary and install-time script inspection.
4. Typosquatting detection.
5. Optional PyPI/source lookup and cache.
6. Local private registry.
7. Private runner with explicit isolation limitations.
8. Tool judgement and private-first agent policy.
9. Cloud/model-backed review as an optional future service.

## License

MIT License. See [LICENSE](LICENSE).

Repository: <https://github.com/devlukeg/pkgwhy>

Issues: <https://github.com/devlukeg/pkgwhy/issues>

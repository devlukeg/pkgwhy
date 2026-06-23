# pkgwhy

Know why a package exists before you or your agent trusts it.

`pkgwhy` is an offline-first Python package intelligence CLI owned and maintained by Luke Gerakiteys. It explains installed packages, inspects local package files without importing them, reports conservative static security signals, and produces agent-readable JSON judgements.

## Status

`pkgwhy` is in local release-candidate readiness review. It is useful for local package inspection experiments, conservative static package review, agent decision-support prototypes, and feedback on the CLI and local private-registry shape.

It is not a production security scanner, not malware-detection certainty, and not a sandbox. Results are evidence and signals for review, not proof that a package is safe or malicious.

Current packaged version candidate: `0.1.0a0`.

## What Works Now

The current preview includes installed package intelligence:

```bash
pkgwhy scan
pkgwhy explain typer
pkgwhy why typer
pkgwhy inspect typer
pkgwhy judge typer --json
pkgwhy risk typer
pkgwhy audit --limit 5 --json
# "reqeusts" is intentionally misspelled to demonstrate typo detection.
pkgwhy typos reqeusts pandas-stubs
```

Implemented capabilities include:

- Installed distribution metadata using `importlib.metadata`.
- Package explanation from local knowledge and installed metadata.
- Direct, transitive, imported, unknown, and not-installed dependency status.
- Simple `requirements.txt`, `pyproject.toml`, `uv.lock`, and `poetry.lock` dependency reasoning.
- Installed package size and largest-file reporting.
- Source availability and coarse readability signals.
- JavaScript readability, minification, and suspicious static signals.
- Native compiled file, WASM, shell script, package-manager, setup/install-time, and CLI-entrypoint signals from file metadata.
- AST-only Python source scanning for filesystem, network, subprocess, environment, credential-pattern, dynamic-code, deserialisation, and encoded-payload signals.
- Typosquatting similarity signals with false-positive guards for common ecosystem package families.
- Conservative risk level, decision, warning, recommendation, evidence, and confidence output.
- Stable JSON output for agent workflows.

The local private-tool MVP supports a local registry, local publishing, tool judgement, and controlled local execution:

```bash
pkgwhy registry init ~/.pkgwhy/registry
pkgwhy publish ./my_tool.py
pkgwhy tool inspect local/my_tool
pkgwhy tool judge local/my_tool --json
pkgwhy run local/my_tool
```

`pkgwhy run` resolves tools only from the configured local registry, verifies the stored bundle hash before execution, runs simple Python-script entrypoints in a per-tool virtual environment, and writes execution metadata logs under the registry directory.

Every run prints this warning:

```text
This run uses a Python virtual environment for dependency isolation. It does not fully sandbox operating-system permissions.
```

## What Is Not Implemented Yet

These are roadmap items, not current features:

- Optional PyPI/source lookup and cache.
- Vulnerability database integration.
- Cloud/private remote registry backends.
- `pull`, mirroring, and remote synchronization.
- Tool dependency installation in the runner.
- Tool bundle signing and signature verification.
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

Install directly from GitHub after the repository is public, or from an authorized private checkout:

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

`pkgwhy` is intended to grow into a private, security-aware executable layer for Python tools and AI-agent skills. The current MVP is local-only:

```bash
pkgwhy registry init ~/.pkgwhy/registry
pkgwhy publish ./my_tool.py
pkgwhy run local/my_tool
pkgwhy tool judge local/my_tool --json
```

The runner executes only tools resolved from the configured local registry. It does not run arbitrary public package code, does not install tool dependencies in the MVP, and blocks execution if the stored bundle hash does not verify.

The MVP runner uses Python virtual environments for dependency isolation. A virtual environment is not a full operating-system sandbox, and `pkgwhy` states that clearly before each run.

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

1. Complete public `0.1.0` release review and packaging.
2. Optional PyPI/source lookup and cache.
3. Local private registry.
4. Private runner with explicit isolation limitations.
5. Tool judgement and private-first agent policy.
6. Cloud/model-backed review as an optional future service.

## License

MIT License. See [LICENSE](LICENSE).

Repository: <https://github.com/devlukeg/pkgwhy>

Issues: <https://github.com/devlukeg/pkgwhy/issues>

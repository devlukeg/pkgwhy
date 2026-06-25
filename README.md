# pkgwhy

Know why a package exists before you or your agent trusts it.

`pkgwhy` is an offline-first Python package intelligence and local private-tool CLI. It explains installed packages, inspects local package files without importing them, reports conservative vulnerability, provenance, and static security signals, produces agent-readable JSON judgements, and can publish and run local private Python tools from a local registry.

## Status

`pkgwhy` is in pre-alpha readiness review for the `0.4.0a0` candidate. It is useful for local package inspection experiments, conservative static package review, agent decision-support prototypes, and feedback on the CLI and local private-registry shape.

It is not a production security scanner, not malware-detection certainty, and not a sandbox. Results are evidence and signals for review, not proof that a package is safe or malicious.

Current packaged version candidate: `0.4.0a0`.

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
pkgwhy audit --limit 5 --json --vulnerability-file ./osv-fixture.json
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
- JavaScript readability, minification, source-map, encoded-payload, dynamic-execution, and obfuscation-like static signals.
- Native compiled file, executable, WASM, shell script, package-manager, setup/install-time, and CLI-entrypoint signals from file metadata.
- AST-only Python source scanning with file/line evidence for filesystem, network, subprocess, environment, credential-pattern, dynamic-code, dynamic-import, deserialisation, unsafe YAML load, package-manager, and encoded-payload signals.
- URL/domain extraction from small source/text files as evidence, not proof of network behavior.
- Conservative credential-like assignment detection with suspicious values masked in output.
- Typosquatting similarity signals with false-positive guards for common ecosystem package families.
- Optional OSV-like vulnerability record parsing from local JSON files.
- Explicit opt-in OSV.dev query boundary for known-vulnerability lookup.
- Conservative version matching for affected and fixed version ranges.
- Metadata-derived provenance/source-trust fields from installed metadata, with unsupported attestation and trusted-publishing checks marked as unknown or not implemented.
- Conservative risk level, decision, warning, recommendation, evidence, confidence, risk model version, and rule-ID output.
- Human `inspect`, `risk`, and `judge` reports that show compact rule-evidence summaries, while JSON reports include structured rule details.
- Stable JSON output for agent workflows.

The local private-tool MVP supports a local registry, local publishing, tool judgement, and controlled local execution:

```bash
pkgwhy registry init ~/.pkgwhy/registry
pkgwhy registry list
pkgwhy registry add local-copy ~/.pkgwhy/registry
pkgwhy registry use local
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

Current runner policy is intentionally conservative:

- Unknown tools are not resolved or run; a valid local registry entry is required.
- Bundle hash mismatch or a missing bundle blocks execution.
- `sandbox_only` and `block` tool judgements block execution.
- Non-interactive execution is blocked unless both the judgement and manifest agent policy allow it.
- Tools with declared dependencies are not run yet because dependency installation is not implemented.
- Unsupported entrypoints, including shell scripts, absolute paths, and path traversal, are rejected.
- Tool signatures report `not_implemented`; unsigned local tools are a manual-review signal, not a verified trust claim.

## What Is Not Implemented Yet

These are roadmap items, not current features:

- Complete vulnerability database coverage, transitive vulnerability analysis, or guaranteed advisory freshness.
- Default online vulnerability lookup. Network access is only used when explicitly requested.
- Cached PyPI/source lookup.
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

Future PyPI pre-alpha install command, once a release is published:

```bash
python -m pip install pkgwhy
```

Runtime dependencies are intentionally small:

- `typer` for the command-line interface.
- `rich` for terminal tables and formatted human output.
- `pydantic` for stable structured judgement, manifest, registry, and report models.
- `packaging` for dependency and requirement parsing.

Development-only dependencies are `pytest`, `build`, and `twine`.

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

Run a conservative risk report:

```bash
pkgwhy risk typer
```

Audit a small slice of the current environment:

```bash
pkgwhy audit --limit 2 --json
```

Include controlled local OSV-like vulnerability data in an audit:

```bash
pkgwhy audit --limit 2 --json --vulnerability-file ./osv-response.json
```

Query OSV.dev explicitly during an audit:

```bash
pkgwhy audit --limit 2 --json --osv
```

Vulnerability data can be incomplete or unavailable. `pkgwhy` reports source-attributed matches and fixed versions only when the supplied advisory data contains them.

Check package names for typosquatting similarity signals:

```bash
pkgwhy typos reqeusts pandas-stubs
```

Create and select a local registry:

```bash
pkgwhy registry init ~/.pkgwhy/registry
pkgwhy registry list
pkgwhy registry use local
```

Add an existing local registry directory:

```bash
pkgwhy registry add work-tools ~/.pkgwhy/work-tools-registry
```

Publish and inspect a local Python script:

```bash
pkgwhy publish ./my_tool.py
pkgwhy tool inspect local/my_tool
pkgwhy tool judge local/my_tool --json
```

Publish a folder with an explicit `pkgwhy.toml` manifest:

```toml
[tool]
name = "my-tool"
owner = "local"
version = "0.1.0"
description = "Local Python tool."
artifact_type = "folder"
entrypoint = "main.py"
python_requires = ">=3.11"
dependencies = []
declared_permissions = ["filesystem"]

[security]
requires_human_approval = true
allow_unsigned = false
allow_unpinned_dependencies = false
signing_status = "not_implemented"

[agent]
default_decision = "review_manually"
non_interactive_decision = "review_manually"
```

```bash
pkgwhy publish ./my-tool-folder
```

Run a local private tool after hash verification and policy checks:

```bash
pkgwhy run local/my_tool
```

## Agent JSON Contracts

Package judgement schema version: `pkgwhy.package_judgement.v1`.

Field shape for `pkgwhy judge <package> --json`:

```json
{
  "schema_version": "pkgwhy.package_judgement.v1",
  "risk_model_version": "pkgwhy.risk_model.v1",
  "package": "package-name",
  "version": "installed-version-or-null",
  "decision": "allow_with_caution",
  "risk_level": "medium",
  "confidence": "medium",
  "summary": "summary from installed metadata or local explanation sources",
  "source_availability": "installed_source_present",
  "installed_size_bytes": 0,
  "detected_capabilities": [],
  "warnings": [],
  "recommendation": "conservative recommendation text",
  "evidence": [],
  "risk_rules": [],
  "known_vulnerabilities": [],
  "provenance": {
    "package": "package-name",
    "version": "installed-version-or-null",
    "repository_url": null,
    "documentation_url": null,
    "homepage_url": null,
    "project_urls": {},
    "metadata_source": "installed_distribution_metadata",
    "source_distribution_status": "unknown",
    "trusted_publishing_status": "unknown",
    "attestation_status": "not_implemented",
    "release_activity_status": "unknown",
    "confidence": "low",
    "warnings": [],
    "evidence": []
  },
  "capability_exposure_note": "Python packages run with the same permissions as the Python process. This analysis detects capabilities used or referenced by package code and metadata; static signals are not proof of runtime behavior or intent."
}
```

Values are environment-specific. Run `pkgwhy judge <installed-package> --json` locally for actual installed-package evidence.

Tool judgement schema version: `pkgwhy.tool_judgement.v1`.

Field shape for `pkgwhy tool judge <tool> --json`:

```json
{
  "schema_version": "pkgwhy.tool_judgement.v1",
  "tool": "local/my_tool",
  "owner": "local",
  "name": "my_tool",
  "version": "0.1.0",
  "decision": "review_manually",
  "risk_level": "medium",
  "confidence": "medium",
  "reason": "Tool bundle hash matches the local registry index.",
  "requires_human_approval": true,
  "manifest": {
    "schema_version": "pkgwhy.tool_manifest.v1",
    "name": "my_tool",
    "owner": "local",
    "version": "0.1.0",
    "description": "Local Python script published with pkgwhy.",
    "artifact_type": "script",
    "entrypoint": "my_tool.py",
    "python_requires": ">=3.11",
    "dependencies": [],
    "declared_permissions": [],
    "security": {
      "requires_human_approval": true,
      "allow_unsigned": false,
      "allow_unpinned_dependencies": false,
      "signing_status": "not_implemented"
    },
    "agent": {
      "default_decision": "review_manually",
      "non_interactive_decision": "review_manually"
    }
  },
  "declared_permissions": [],
  "detected_capabilities": [],
  "hash_status": "verified",
  "signature_status": "not_implemented",
  "warnings": [
    "Signature verification is not implemented yet.",
    "Static capability detection for tool bundles is not implemented yet."
  ],
  "recommendation": "Review declared permissions and manifest metadata before running this private tool."
}
```

Supported package and tool decision values are:

- `allow`
- `allow_with_caution`
- `review_manually`
- `sandbox_only`
- `block`

Supported risk levels are:

- `low`
- `medium`
- `high`
- `critical`
- `unknown`

## Security Model

`pkgwhy` is static and metadata-first. It must not import or execute inspected packages merely to inspect them.

Python packages do not have browser or mobile style permissions. They usually run with the same operating-system permissions as the Python process and user executing them. `pkgwhy` therefore reports capability exposure signals, not guaranteed permissions.

Examples of static signals:

- A source file references `subprocess.run`.
- A package declares console scripts.
- Installed files include native compiled extensions.
- AST parsing finds `eval`, `exec`, `pickle.loads`, or environment-variable access.
- Source text contains URL/domain references.
- Source text contains credential-like assignment names, with suspicious values masked.
- JavaScript files appear minified, reference `eval`, reference `atob`, include source maps, or contain obfuscation-like patterns.

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

Risk rule output includes `risk_model_version` and per-rule `rule_id`, category, severity, confidence, message, evidence, optional file path, optional line number, optional symbol, and false-positive notes. These rule IDs are a pre-alpha stability candidate, not a long-term compatibility guarantee yet.

Current pre-alpha rule IDs:

- `PKGWHY-VULN-001`: known vulnerability advisory match.
- `PKGWHY-RISK-001`: possible typosquatting similarity.
- `PKGWHY-RISK-002`: unknown source availability from installed files.
- `PKGWHY-RISK-003`: missing license metadata.
- `PKGWHY-RISK-004`: native compiled code present.
- `PKGWHY-RISK-005`: static capability signal.
- `PKGWHY-RISK-006`: no installed files found through distribution metadata.
- `PKGWHY-PY-001`: Python dynamic code execution reference.
- `PKGWHY-PY-002`: Python dynamic import reference.
- `PKGWHY-PY-003`: Python deserialisation-risk reference.
- `PKGWHY-PY-004`: Python encoded-payload handling reference.
- `PKGWHY-PY-005`: Python subprocess or shell execution reference.
- `PKGWHY-PY-006`: Python environment or secret-like access reference.
- `PKGWHY-PY-007`: Python package-manager manipulation reference.
- `PKGWHY-PY-008`: Python unsafe YAML load reference.
- `PKGWHY-PY-009`: Python obfuscation-bootstrap signal.
- `PKGWHY-BUILD-001`: executable `setup.py` present.
- `PKGWHY-BUILD-002`: setup-time subprocess or shell reference.
- `PKGWHY-BUILD-003`: setup-time network reference.
- `PKGWHY-BUILD-004`: setup-time dynamic execution reference.
- `PKGWHY-BUILD-005`: build backend declared.
- `PKGWHY-BUILD-006`: `setup.cfg` present.
- `PKGWHY-NET-001`: source URL or domain reference.
- `PKGWHY-CRED-001`: credential-like assignment with value masked.
- `PKGWHY-JS-001`: JavaScript minification or density signal.
- `PKGWHY-JS-002`: JavaScript dynamic execution reference.
- `PKGWHY-JS-003`: JavaScript encoded-payload signal.
- `PKGWHY-JS-004`: JavaScript obfuscation-like signal.
- `PKGWHY-JS-005`: JavaScript source-map reference.
- `PKGWHY-BIN-001`: native extension or library present.
- `PKGWHY-BIN-002`: WASM binary present.
- `PKGWHY-BIN-003`: native executable present.

Known-vulnerability output is source-attributed. A missing vulnerability match does not prove that a package has no vulnerabilities, because advisory databases and local fixtures can be incomplete or unavailable.

Native extensions, WASM files, minified JavaScript, URL references, and credential-like names are not automatically malicious. They are evidence for review, and the surrounding package purpose and source context still matter.

## Private Registry Roadmap

`pkgwhy` is intended to grow into a private, security-aware executable layer for Python tools and AI-agent skills. The current MVP is local-only:

```bash
pkgwhy registry init ~/.pkgwhy/registry
pkgwhy publish ./my_tool.py
pkgwhy tool inspect local/my_tool
pkgwhy tool judge local/my_tool --json
pkgwhy run local/my_tool
```

The runner executes only tools resolved from the configured local registry. It does not run arbitrary public package code, does not install tool dependencies in the MVP, and blocks execution if the stored bundle hash does not verify. Local registry entries are file-backed records under the configured registry path; no cloud registry, account, upload, pull, or remote sync is implemented in this preview.

The MVP runner uses Python virtual environments for dependency isolation. A virtual environment is not a full operating-system sandbox, and `pkgwhy` states that clearly before each run:

```text
This run uses a Python virtual environment for dependency isolation. It does not fully sandbox operating-system permissions.
```

Signing is also not implemented yet, so JSON judgement reports `signature_status: "not_implemented"` rather than pretending a signature was verified.

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

1. Complete public release review and packaging for the current local package-intelligence, registry, tool-judgement, and runner MVP.
2. Optional PyPI/source lookup and cache.
3. Tool dependency installation in the runner.
4. Tool bundle signing and signature verification.
5. Cloud/private remote registry backends.
6. Cloud/model-backed review as an optional future service.

## License

MIT License. See [LICENSE](LICENSE).

Repository: <https://github.com/devlukeg/pkgwhy>

Issues: <https://github.com/devlukeg/pkgwhy/issues>

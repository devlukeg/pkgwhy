# pkgwhy

Know why a package exists before you or your agent trusts it.

`pkgwhy` is an offline-first Python package intelligence, agent policy, and local private-tool CLI. It explains installed packages, inspects local package files without importing them, reports conservative vulnerability, provenance, and static security signals, produces agent-readable JSON judgements, and can publish and run local private Python tools from a local registry.

## Status

`pkgwhy` 1.0.0 is a Python supply-chain security decision-support tool for developers and AI agents. It is useful for local package inspection, conservative static package review, agent-readable JSON, vulnerability and provenance foundations, policy checks, and the local private-registry and runner MVP.

It is not a production security scanner, not malware-detection certainty, and not a full sandbox. Results are evidence and signals for review, not proof that a package is safe or malicious.

Current packaged version: `1.0.0`.

## What Works Now

The current release includes installed package intelligence:

```bash
pkgwhy scan
pkgwhy explain typer
pkgwhy why typer
pkgwhy inspect typer
pkgwhy judge typer --json
pkgwhy agent policy --json
pkgwhy agent precheck typer --json
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
- Explicit opt-in OSV.dev query boundary for known-vulnerability lookup, with a local response cache and stale-cache fallback when a requested online lookup is unavailable.
- Conservative version matching for affected and fixed version ranges.
- Metadata-derived provenance/source-trust fields from installed metadata and optional PyPI JSON, with unsupported attestation and trusted-publishing checks marked as unknown or not implemented.
- Conservative risk level, decision, warning, recommendation, evidence, confidence, risk model version, and rule-ID output.
- Human `inspect`, `risk`, and `judge` reports that show compact rule-evidence summaries, while JSON reports include structured rule details.
- Stable JSON output for agent workflows.
- Schema-versioned agent policy and package precheck output.
- Conservative non-interactive agent defaults that block unknown or high-risk package use until a human reviews the evidence.
- Compact local agent decision logs that omit full package evidence.

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
pkgwhy run local/my_tool --non-interactive
```

`pkgwhy run` resolves tools only from the configured local registry, verifies the stored bundle hash before execution, runs simple Python-script entrypoints in a per-tool virtual environment, and writes execution metadata logs under the registry directory.

Every run prints this warning:

```text
This run uses a Python virtual environment for dependency isolation. It does not fully sandbox operating-system permissions.
```

Current runner policy is intentionally conservative:

- Unknown tools are not resolved or run; a valid local registry entry is required.
- Duplicate owner/name/version publishes are blocked instead of silently replacing a registry entry.
- Corrupt registry indexes fail closed for publish and tool-judgement paths.
- Symlinks are not bundled, and stored registry paths must remain inside the registry root.
- Bundle hash mismatch or a missing bundle blocks execution.
- `sandbox_only` and `block` tool judgements block execution.
- Non-interactive execution is blocked unless both the judgement and manifest agent policy allow it.
- Tools with declared dependencies are not run yet because dependency installation is not implemented.
- Unsupported entrypoints, including shell scripts, absolute paths, and path traversal, are rejected.
- Tool signatures report `not_implemented`; unsigned local tools are a manual-review signal, not a verified trust claim.
- Successful run logs include the pre-run policy decision, reasons, and warnings.

## What Is Not Implemented Yet

These are roadmap items, not current features:

- Complete vulnerability database coverage, transitive vulnerability analysis, or guaranteed advisory freshness.
- Default online vulnerability lookup. Network access is only used when explicitly requested.
- Cached PyPI/source lookup beyond the current OSV response cache.
- Cloud/private remote registry backends.
- `pull`, mirroring, and remote synchronization.
- Tool dependency installation in the runner.
- Tool bundle signing and signature verification.
- Dynamic sandbox analysis for arbitrary packages.
- Tool-specific `pkgwhy agent judge` expansion beyond the current package precheck path.
- `pkgwhy agent explain-decision <review-id>`.
- Cloud/model-backed review.
- Billing, API keys, team plans, or enterprise deployment.
- OS-level sandboxing or container isolation.
- Production security-tool guarantees.

## Install

Install from PyPI after the release is published:

```bash
python -m pip install pkgwhy
```

For local development from this repository:

```bash
python -m pip install -e ".[dev]"
pkgwhy --help
```

Install directly from GitHub after the repository is public, or from an authorized private checkout:

```bash
python -m pip install "pkgwhy @ git+https://github.com/devlukeg/pkgwhy.git"
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

Inspect the default agent policy and run a conservative agent precheck:

```bash
pkgwhy agent policy --json
pkgwhy agent precheck typer --json
pkgwhy agent judge typer --json
```

`pkgwhy agent precheck` applies policy to the package judgement. In the default non-interactive mode, unknown and high-risk package decisions are blocked until a human reviews the judgement evidence. The command writes a compact local decision log under the user config directory when that directory is writable and does not install, import, or execute the package.

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

Use a specific OSV cache directory:

```bash
pkgwhy audit --limit 2 --json --osv --osv-cache-dir ./.pkgwhy-osv-cache
```

Query PyPI JSON explicitly for provenance metadata during an audit:

```bash
pkgwhy audit --limit 2 --json --pypi
```

Vulnerability data can be incomplete or unavailable. `pkgwhy` reports source-attributed matches and fixed versions only when the supplied advisory data contains them. Cached OSV responses can be stale, and missing vulnerability matches are not evidence that a package is safe.

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

Apply the stricter non-interactive runner policy:

```bash
pkgwhy run local/my_tool --non-interactive
```

## Agent JSON Contracts

Compatibility policy: [docs/json-schema-compatibility.md](docs/json-schema-compatibility.md).

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

Agent policy schema version: `pkgwhy.agent_policy.v1`.

Field shape for `pkgwhy agent policy --json`:

```json
{
  "schema_version": "pkgwhy.agent_policy.v1",
  "allow_public_pypi": false,
  "allow_unpinned_dependencies": false,
  "allow_unsigned_tools": false,
  "require_pkgwhy_judgement": true,
  "require_hash_verification": true,
  "require_signature_verification": false,
  "non_interactive_default_decision": "block",
  "unknown_package_decision": "review_manually",
  "high_risk_package_decision": "review_manually",
  "critical_risk_package_decision": "block",
  "non_interactive_unknown_package_decision": "block",
  "non_interactive_high_risk_package_decision": "block",
  "non_interactive_critical_risk_package_decision": "block",
  "tool_execution_requires_local_registry": true,
  "dynamic_analysis_default_decision": "block"
}
```

Agent package precheck schema version: `pkgwhy.agent_package_precheck.v1`.

Field shape for `pkgwhy agent precheck <package> --json`:

```json
{
  "schema_version": "pkgwhy.agent_package_precheck.v1",
  "policy_schema_version": "pkgwhy.agent_policy.v1",
  "package": "package-name",
  "version": "installed-version-or-null",
  "target_type": "package",
  "non_interactive": true,
  "decision": "block",
  "risk_level": "unknown",
  "confidence": "low",
  "policy_decision_source": "agent_policy",
  "reasons": [],
  "warnings": [],
  "recommendation": "conservative recommendation text",
  "package_judgement": {
    "schema_version": "pkgwhy.package_judgement.v1"
  }
}
```

The embedded `package_judgement` contains the same package judgement shape as `pkgwhy judge --json`. Compact local agent decision logs use `pkgwhy.agent_decision_log.v1` and intentionally omit the full judgement evidence.

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

`pkgwhy` is static and metadata-first. Package inspection reads metadata, files, text, and AST without importing or executing inspected packages.

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

## Dynamic Sandbox Roadmap

Dynamic analysis has an experimental command skeleton, but it is not part of the stable security decision surface in this release. Dynamic analysis intentionally executes code, so it has a different safety boundary from static inspection.

The current release includes no arbitrary package dynamic analysis, no container backend, and no production sandboxing claim. The command remains as a safe-fail surface for the intended JSON shape and safety boundary.

The design is documented in [docs/dynamic-sandbox.md](docs/dynamic-sandbox.md). The key constraints are:

- static package inspection remains the default;
- unknown package code is not run on the host;
- no arbitrary dynamic package installation, import, or CLI execution;
- a future dynamic backend should use a disposable sandbox boundary;
- network should be off by default;
- filesystem access should default to a temporary scratch directory;
- host secrets should not be inherited;
- missing sandbox backends should fail safely instead of falling back to host execution;
- empty event lists are not proof of safety.

The current command surface is a safe-fail skeleton:

```bash
pkgwhy dynamic --help
pkgwhy dynamic inspect --help
pkgwhy dynamic inspect demo-target --container --network off
```

Until a sandbox backend exists, `pkgwhy dynamic inspect` refuses to execute the target and reports that the backend is unavailable or blocked.

`pkgwhy run` is still a separate local private-tool execution path and is not dynamic package analysis.

Dynamic analysis result schema version: `pkgwhy.dynamic_analysis.v1`.

Field shape for `pkgwhy dynamic inspect <target> --container --json` while no backend is available:

```json
{
  "schema_version": "pkgwhy.dynamic_analysis.v1",
  "target": "target-name",
  "mode": "inspect",
  "sandbox_backend": "container",
  "network_mode": "off",
  "filesystem_mode": "scratch",
  "status": "backend_unavailable",
  "warnings": [],
  "process_events": [],
  "filesystem_events": [],
  "network_events": [],
  "decision": "block",
  "limitations": []
}
```

Event lists are populated only when a future backend actually observes events. Empty event lists are not proof of safety.

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

Risk rule output includes `risk_model_version` and per-rule `rule_id`, category, severity, confidence, message, evidence, optional file path, optional line number, optional symbol, and false-positive notes. These rule IDs are a 1.0.0 compatibility surface; incompatible changes require changelog coverage and may require a schema or catalog version bump.

Detailed rule categories, corpus strategy, compatibility expectations, and false-positive/false-negative limitations are documented in [`docs/static-rule-corpus.md`](docs/static-rule-corpus.md).

Current 1.0.0 rule IDs:

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

## Private Registry And Agent Policy

`pkgwhy` is intended to grow into a private, security-aware executable layer for Python tools and AI-agent skills. The current MVP uses a local registry:

```bash
pkgwhy registry init ~/.pkgwhy/registry
pkgwhy publish ./my_tool.py
pkgwhy tool inspect local/my_tool
pkgwhy tool judge local/my_tool --json
pkgwhy run local/my_tool
```

The runner executes only tools resolved from the configured local registry. It does not run arbitrary public package code, does not install tool dependencies in the MVP, and blocks execution if the stored bundle hash does not verify. Local registry entries are file-backed records under the configured registry path; no cloud registry, account, upload, pull, or remote sync is implemented in this release.

The `1.0.0` release includes policy-as-code foundations for agents:

- `pkgwhy agent policy` shows conservative default policy.
- `pkgwhy agent precheck <package> --json` applies policy to package judgement JSON.
- `pkgwhy agent judge <package> --json` is currently a package precheck alias.
- Non-interactive package prechecks block unknown and high-risk package decisions by default.
- Agent decision logs are local, compact, best-effort when the config directory is writable, and do not include full static evidence.

The MVP runner uses Python virtual environments for dependency isolation. A virtual environment is not a full operating-system sandbox, and `pkgwhy` states that clearly before each run:

```text
This run uses a Python virtual environment for dependency isolation. It does not fully sandbox operating-system permissions.
```

Signing is also not implemented yet, so JSON judgement reports `signature_status: "not_implemented"` rather than pretending a signature was verified.

## Future Cloud Review

The local/free product will remain offline-first: metadata inspection, AST scanning, capability signals, local risk rules, and local JSON judgement.

A future paid cloud/model-backed review layer may add deeper review over retrieved package evidence, review IDs, cached results, richer policy decisions, usage logs, privacy controls, and enterprise/private deployment options. Billing and cloud review are not implemented in this release.

## Development

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
```

Release and process references:

- [Release Checklist](docs/release-checklist.md)
- [Versioning Policy](docs/versioning-policy.md)
- [JSON Schema Compatibility](docs/json-schema-compatibility.md)
- [1.0.0 Feature Surface](docs/release-candidate-surface.md)
- [Threat Model](docs/threat-model.md)
- [Production Readiness Blockers](docs/production-readiness.md)

## Roadmap

1. Expand agent policy validation, tool-specific agent judgement, and decision explanation.
2. Broader optional PyPI/source lookup and cache.
3. Tool dependency installation in the runner.
4. Tool bundle signing and signature verification.
5. Cloud/private remote registry backends.
6. Cloud/model-backed review as an optional future service.

## License

MIT License. See [LICENSE](LICENSE).

Repository: <https://github.com/devlukeg/pkgwhy>

Issues: <https://github.com/devlukeg/pkgwhy/issues>

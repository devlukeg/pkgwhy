# JSON Schema Compatibility

`pkgwhy` JSON output is intended for conservative decision support by humans and agents. It is not a safety guarantee, malware verdict, or sandboxing claim.

Public command JSON is offline-first by default. Optional online enrichment, such as explicit OSV.dev or PyPI lookups, may add source-attributed evidence, warnings, or status values to the same public schemas without requiring a different schema for offline use or guaranteeing non-empty vulnerability, provenance, attestation, or release-activity fields. When enrichment is unavailable, fields may remain empty, `unknown`, `unavailable`, or `not_implemented`.

Current public JSON contracts:

- `pkgwhy.package_judgement.v1` for `pkgwhy judge <package> --json` and embedded package judgements.
- `pkgwhy.precheck.v1` for `pkgwhy precheck <package> --json`.
- `pkgwhy.precheck_batch.v1` for `pkgwhy precheck -r requirements.txt --json` and `pkgwhy precheck pyproject.toml --json`.
- `pkgwhy.pip_install_gate.v1` for `pkgwhy pip install <package> --json` and `pkgwhy pip install -r requirements.txt --json`.
- `pkgwhy.audit.v2` for `pkgwhy audit --json`.
- `pkgwhy.agent_policy.v1` for `pkgwhy agent policy --json`.
- `pkgwhy.agent_package_precheck.v1` for `pkgwhy agent precheck <package> --json` and `pkgwhy agent judge <package> --json`.
- `pkgwhy.tool_judgement.v1` for `pkgwhy tool judge <tool> --json`, including local registry `trust_state`.
- `pkgwhy.tool_manifest.v1` for local private-tool manifests embedded in tool judgement JSON.
- `pkgwhy.dynamic_analysis.v1` for experimental dynamic-analysis JSON.

## Compatibility Rules

During the current 1.x release line, schema versions are compatibility surfaces for agent workflows. Changes should be deliberate:

- Additive optional fields may keep the same schema version when existing consumers can ignore them safely.
- Required field additions, removals, renamed fields, enum meaning changes, or nested shape changes must bump the affected schema version.
- Rule ID meaning changes that affect `risk_rules` should update the static rule catalog version or the affected output schema version.
- Schema versions are not reused for different incompatible shapes.
- Compatibility changes must be documented in `CHANGELOG.md`.

## Test Coverage

The test suite includes normalized golden snapshots or focused schema validation for:

- `pkgwhy judge <package> --json`
- `pkgwhy precheck <package> --json`
- `pkgwhy precheck -r requirements.txt --json`
- `pkgwhy precheck pyproject.toml --json`
- `pkgwhy pip install <package> --json`
- `pkgwhy pip install -r requirements.txt --json`
- `pkgwhy audit --json`
- `pkgwhy agent precheck <package> --json`
- `pkgwhy agent judge <package> --json`
- `pkgwhy tool judge <tool> --json`

Snapshots normalize environment-specific values and pin stable field sets, schema versions, nested schema keys, provenance status values, policy decisions, and hash/signature status values. They intentionally avoid treating a missing vulnerability match as evidence of safety.

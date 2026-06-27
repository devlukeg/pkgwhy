# Changelog

## 0.9.0a0 - Unreleased pre-alpha

- Choose dynamic analysis Option B for the `1.0.0` readiness line: dynamic analysis remains experimental and out of scope for production security guarantees.
- Keep `pkgwhy dynamic inspect` as a safe-fail CLI skeleton that refuses host execution of unknown package code and does not invoke Docker or run containers.
- Add tests that assert the dynamic result warnings and limitations carry the explicit Option B boundary.

## 0.8.0a0 - Unreleased pre-alpha

- Start static rule corpus/schema hardening with a versioned static rule catalog snapshot.
- Add stable rule ID ordering helpers and tests to catch accidental rule renames, removals, or reordering.
- Add static rule corpus documentation covering rule categories, rule families, fixture strategy, and compatibility expectations.
- Add controlled Python static-signal corpus fixtures for dynamic execution, dynamic imports, deserialisation, encoded payloads, subprocess/package-manager use, environment access, URL/domain extraction, and credential masking.
- Add controlled JavaScript, native, WASM, shell, and build-file corpus fixtures with false-positive coverage for JavaScript call-like substrings.
- Add normalized golden JSON snapshot tests and schema compatibility policy documentation for agent-facing package, audit, precheck, and tool judgement output.
- Document static rule ID lifecycle, evidence location expectations, corpus fixture coverage, and false-positive/false-negative limitations.
- Harden OSV response decoding, audited-version PyPI provenance status, rule catalog snapshots, and JSON/static corpus regression tests.

## 0.7.0a0 - Unreleased pre-alpha

- Harden explicit OSV.dev audit lookups with a local response cache, stale-cache fallback, cache status warnings, and continued offline-by-default behavior.
- Keep vulnerability matching conservative by treating OSV `limit` events as upper bounds, not fixed-version recommendations.
- Add advisory source URL evidence to known-vulnerability matches and audit-level vulnerability/provenance source summaries.
- Bump audit JSON output to `pkgwhy.audit.v2` for the expanded source summary fields.
- Add optional `pkgwhy audit --pypi` provenance lookup from PyPI JSON without inferring Trusted Publishing or attestation status.
- Report PyPI source distribution presence only when PyPI file metadata actually lists a source archive.
- Add tests for OSV parsing, matching, caching, source attribution, PyPI provenance, and audit integration.
- Document that cached advisory data can be stale and that missing vulnerability matches are not proof of safety.

## 0.6.0a0 - Unreleased pre-alpha

- Add schema-versioned agent policy defaults with conservative non-interactive decisions for package use.
- Add `pkgwhy agent policy`, `pkgwhy agent precheck <package> --json`, and package-focused `pkgwhy agent judge <package> --json`.
- Add schema-versioned agent package precheck output that embeds the package judgement and records policy reasons.
- Add compact local agent decision logs that omit full package evidence.
- Harden local registry publish and judgement paths by failing closed on corrupt registry indexes.
- Block duplicate owner/name/version publishes instead of silently replacing existing registry entries.
- Reject symlinked tool bundle members during local publish and keep stored registry paths bounded to the registry root during tool judgement.
- Add `pkgwhy run --non-interactive` to apply stricter tool execution policy from the CLI.
- Include successful pre-run policy decision, reasons, and warnings in local tool execution logs.
- Continue to treat signatures as `not_implemented` and virtual environments as dependency isolation only, not OS sandboxing.

## 0.5.0a0 - Unreleased pre-alpha

- Start the experimental dynamic sandbox design phase without enabling arbitrary dynamic package execution.
- Add a dynamic sandbox threat model covering static-vs-dynamic boundaries, no-host-execution defaults, network-off defaults, scratch filesystem expectations, no-secrets constraints, event model goals, and current limitations.
- Add a safe-fail `pkgwhy dynamic inspect` command skeleton that refuses host execution until a sandbox backend exists.
- Add schema-versioned dynamic analysis result models with empty event lists unless a backend actually observes events.
- Add controlled fixture-only dynamic execution test support that runs only local test fixtures under a fixture root with a scratch working directory and minimal environment.
- Add a Docker executable detection boundary for the future container backend without invoking Docker or running containers.
- Document that missing sandbox backends must fail safely rather than falling back to host execution.

## 0.4.0a0 - Unreleased pre-alpha

- Add stronger static-analysis rule evidence while keeping `pkgwhy` in pre-alpha decision-support positioning.
- Add structured file/line/symbol evidence for Python dynamic execution, dynamic imports, deserialisation-risk APIs, unsafe YAML load, encoded-payload handling, subprocess/shell execution, environment/secret-like references, and package-manager manipulation.
- Add static setup/build-file analysis for `setup.py`, `setup.cfg`, and `pyproject.toml` build-backend metadata without running build scripts.
- Add source URL/domain extraction as evidence only, with explicit false-positive notes.
- Add conservative credential-like assignment detection with suspicious values masked in output.
- Add JavaScript rule evidence for minification/density, dynamic execution, encoded-payload handling, source-map references, and obfuscation-like patterns.
- Add native extension, executable, and WASM binary rule evidence while documenting that these artifacts are not automatically malicious.
- Surface compact rule-evidence summaries in human `inspect`, `risk`, and `judge` output while preserving schema-versioned JSON judgement output.

## 0.3.0a0 - Unreleased pre-alpha

- Add a vulnerability/provenance/risk-model foundation while keeping `pkgwhy` in pre-alpha decision-support positioning.
- Add OSV-like vulnerability record models, parser, explicit OSV.dev client boundary, and conservative version-range matching.
- Add optional `pkgwhy audit --vulnerability-file` support for controlled local advisory data and explicit `pkgwhy audit --osv` support for live OSV.dev lookup.
- Add metadata-derived provenance/source-trust summaries to package judgement JSON, with Trusted Publishing, attestation verification, and sdist/wheel comparison marked as unknown or not implemented.
- Add `pkgwhy.risk_model.v1`, rule IDs, rule severity, confidence, and evidence fields to package judgement JSON.
- Document that vulnerability databases can be incomplete and that missing vulnerability matches are not proof of safety.

## 0.2.0a0 - Unreleased pre-alpha

- Prepare the first PyPI/TestPyPI developer-preview candidate with the local registry and runner MVP included.
- Add GitHub repository, homepage, issue, and changelog metadata for `https://github.com/devlukeg/pkgwhy`.
- Start local package intelligence foundation with `scan`, `explain`, `why`, `inspect`, and `judge --json`.
- Add metadata-first inspection, package-size scanning, AST-only Python capability signals, dependency classification, and conservative judgement models.
- Add local registry, local publish, local tool inspect/judge, and local `pkgwhy run` MVP with hash verification, per-tool virtual environments, execution logs, and explicit non-sandboxing warning.
- Add initial local tool execution policy checks for hash verification, non-interactive defaults, unsupported execution modes, unsigned-tool warnings, and deferred dependency installation.
- Document that results are static evidence and decision support, not production security guarantees or malware certainty.

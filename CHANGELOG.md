# Changelog

## 0.5.0a0 - Unreleased pre-alpha

- Start the experimental dynamic sandbox design phase without enabling arbitrary dynamic package execution.
- Add a dynamic sandbox threat model covering static-vs-dynamic boundaries, no-host-execution defaults, network-off defaults, scratch filesystem expectations, no-secrets constraints, event model goals, and current limitations.
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

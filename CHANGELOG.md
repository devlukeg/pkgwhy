# Changelog

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

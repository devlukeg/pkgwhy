# Production Readiness Blockers

This document tracks remaining work before `pkgwhy` can be described as production-ready security decision-support tooling.

`pkgwhy` should not claim final `1.0.0` production readiness until every required item is complete and locally validated.

## Complete For Current Local Candidate

- Source-attributed vulnerability matching with offline-safe local fixtures, optional OSV.dev lookup, and stale-cache fallback.
- Conservative PyPI provenance lookup with `unknown` or `not_implemented` attestation and trusted-publishing fields.
- Stable static rule IDs with severity, confidence, category, false-positive notes, and evidence locations where feasible.
- Corpus fixtures for Python, JavaScript, native, WASM, shell, and build-file signals.
- Golden JSON snapshot tests for package judgement, audit, agent precheck, agent judge, and tool judgement.
- Conservative agent policy defaults for unknown and high-risk non-interactive decisions.
- Local registry and runner hardening for corrupt indexes, duplicate publishes, symlinks, bounded registry paths, missing bundles, hash mismatch, unsupported entrypoints, and explicit non-sandboxing warnings.
- Dynamic analysis Option B: experimental and out of scope for `1.0.0` production security guarantees.

## Remaining Before `1.0.0`

- Remote CI status after an approved push/PR flow.
- Final public docs alignment for the selected release candidate.
- Final security posture review after external review and local checks.
- Confirmation that public responsible disclosure guidance is acceptable for the public repository.
- Decision on whether source distribution versus wheel comparison remains out of scope or needs implementation.
- Decision on whether signing and attestation remain `not_implemented` for `1.0.0` or need a scoped implementation.
- Final release-candidate validation from a clean checkout or fresh environment.

## Explicit Non-Goals For `1.0.0`

- Definitive malware detection.
- Full OS sandboxing.
- Dynamic analysis of arbitrary packages.
- Cloud registry hosting.
- Billing or account management.
- Hosted model-backed review.
- Secret or credential management.
- PyPI/TestPyPI publishing automation configured with real credentials.

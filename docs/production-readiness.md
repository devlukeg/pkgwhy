# Production Readiness Posture

This document tracks the 1.0.0 release posture and the remaining work before `pkgwhy` can make stronger production security claims.

`pkgwhy` 1.0.0 is stable Python supply-chain security decision-support tooling. It should not be described as a production malware scanner, proof of package safety, or a full sandbox.

## Complete For `1.0.0`

- Source-attributed vulnerability matching with offline-safe local fixtures, optional OSV.dev lookup, and stale-cache fallback.
- Conservative PyPI provenance lookup with `unknown` or `not_implemented` attestation and trusted-publishing fields.
- Stable static rule IDs with severity, confidence, category, false-positive notes, and evidence locations where feasible.
- Corpus fixtures for Python, JavaScript, native, WASM, shell, and build-file signals.
- Golden JSON snapshot tests for package judgement, audit, agent precheck, agent judge, and tool judgement.
- Conservative agent policy defaults for unknown and high-risk non-interactive decisions.
- Local registry and runner hardening for corrupt indexes, duplicate publishes, symlinks, bounded registry paths, missing bundles, hash mismatch, unsupported entrypoints, and explicit non-sandboxing warnings.
- Dynamic analysis Option B: experimental and out of scope for `1.0.0` production security guarantees.

## Release Operations Requiring Luke Approval

- Luke review and explicit approval for any push, PR, tag, or publish action.
- Remote CI status after an approved push/PR flow.
- Confirmation that public responsible disclosure guidance is acceptable for the public repository.

## Future Production-Security Hardening

- Final security posture review after external review and public launch feedback.
- Clean-checkout validation on each supported release platform before broader production-security positioning.
- Broader vulnerability database coverage and transitive vulnerability analysis.
- Trusted Publishing, attestation verification, and source distribution versus wheel comparison if implemented with source-attributed evidence.

## Explicit Non-Goals For `1.0.0`

- Definitive malware detection.
- Full OS sandboxing.
- Dynamic analysis of arbitrary packages.
- Cloud registry hosting.
- Billing or account management.
- Hosted model-backed review.
- Secret or credential management.
- PyPI/TestPyPI publishing automation configured with real credentials.

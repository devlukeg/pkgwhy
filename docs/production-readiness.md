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
- Dynamic analysis remains experimental and outside the stable security decision surface for this release.

## Release Operations

- Pushes, pull requests, tags, and publication are handled through the project release process.
- Remote CI should pass before publication.
- Public responsible disclosure guidance should be reviewed before public release.

## Future Production-Security Hardening

- Final security posture review after external review and public launch feedback.
- Clean-checkout validation on each supported release platform before broader production-security positioning.
- Broader vulnerability database coverage and transitive vulnerability analysis.
- Trusted Publishing, attestation verification, and source distribution versus wheel comparison if implemented with source-attributed evidence.

## Current Limitations

- Definitive malware detection.
- Full OS sandboxing.
- Dynamic analysis of arbitrary packages.
- Cloud registry hosting.
- Billing or account management.
- Hosted model-backed review.
- Secret or credential management.
- PyPI/TestPyPI publishing automation configured with real credentials.

# 1.0.0 Feature Surface

This document freezes the `1.0.0` release surface. It describes what is implemented, what remains experimental, and what is future work.

`pkgwhy` is a Python supply-chain security decision-support tool for developers and AI agents. It helps identify dependency risk signals and supports safer package and agent policy decisions. It does not prove packages are safe and does not definitively detect malware.

## Implemented In `1.0.0`

- Offline-first package metadata, explanation, dependency-reasoning, inspection, risk, judgement, audit, and typosquatting commands.
- Static Python AST and file/text analysis without importing or executing inspected package code.
- Static rule evidence with stable rule IDs, severity, confidence, category, evidence, optional file path, optional line number, optional symbol, and false-positive notes.
- Controlled static corpus fixtures and golden JSON snapshot tests.
- Source-attributed vulnerability support from local OSV-like data and explicit optional OSV.dev lookup with cache fallback.
- Optional PyPI JSON provenance lookup with conservative `unknown`, `unavailable`, or `not_implemented` fields where evidence is unavailable.
- Agent-readable JSON for package judgement, audit, agent policy, agent precheck, agent judge, tool judgement, and dynamic safe-fail results.
- Conservative agent policy defaults and compact local decision logs that omit full package evidence.
- Local private registry, local publish, tool inspect, tool judge, and explicit local tool execution through `pkgwhy run`.
- Local runner hash verification, corrupt-index handling, duplicate publish protection, symlink rejection, bounded registry paths, unsupported-entrypoint blocking, and non-sandboxing warning.
- Release checklist, versioning policy, JSON compatibility policy, threat model, production-readiness blocker list, and public trace hygiene script.

## Experimental Or Not Included In The Stable Security Surface

- Dynamic analysis of arbitrary packages is experimental and not part of the stable security decision surface in this release.
- `pkgwhy dynamic inspect` is a safe-fail skeleton. It exposes the intended JSON shape and safety boundary, but refuses host execution and does not invoke Docker or run containers.
- Trusted Publishing verification is not implemented.
- Attestation verification is not implemented.
- Tool bundle signing and signature verification are not implemented.
- Full source distribution versus wheel diffing is not implemented.
- Transitive vulnerability analysis is not implemented.

## Future Work

- Safe opt-in dynamic sandbox backend, if implemented without host execution of unknown code.
- Tool dependency installation under explicit policy controls.
- Tool bundle signing and verification.
- Cloud or remote private registry backends.
- Hosted review or model-backed review over retrieved evidence.
- Additional ecosystem support and broader corpus validation.

## Language Boundaries

Allowed:

- helps identify dependency risk signals;
- supports safer package and agent policy decisions;
- source-attributed vulnerability and provenance evidence;
- conservative static analysis;
- decision support, not a guarantee.

Avoid stronger claims such as:

- proves packages are safe;
- definitively detects all malware;
- fully sandboxes code;
- production malware-scanner guarantees.

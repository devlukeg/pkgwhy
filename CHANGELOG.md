# Changelog

## 1.6.0 - 2026-07-01

- Improve agent JSON consistency across decision commands with shared top-level fields for command, target, recommended next action, exit code, exit-code meaning, evidence summary, source freshness, and policy where available.
- Add `pkgwhy.error.v1` JSON error objects for handled `--json` user/configuration errors in agent-facing gates.
- Improve pyproject precheck routing for explicitly passed TOML files that contain a `[project]` table.
- Add batch precheck summaries: `blocking_targets`, `review_targets`, `allowed_targets`, and `aggregate_recommendation`.
- Add JSON output for registry trust-state commands: `trust`, `review`, `quarantine`, `block`, and `blocked`.
- Make local registry `blocked` and `quarantined` trust states produce blocking `pkgwhy tool judge` decisions without weakening hash, signature, manifest, or static-analysis cautions.
- Add non-executing `pkgwhy tool validate <path> --json` for local private-tool source validation.
- Add static capability analysis for verified local tool bundles during `pkgwhy tool judge`.
- Add `pkgwhy agent check <target> --json` as a safe dispatcher for package specs, requirements files, pyproject-style TOML files, and local tool folders/scripts.
- Document the public agent integration contract, exit-code meanings, batch summary interpretation, pip gate safety model, and registry trust-state effects.
- No cloud services, billing, hosted review, secrets, publishing, or OS-level sandboxing claims were added.

## 1.5.0 - 2026-06-30

- Add `docs/commercial-agent-platform.md` to describe the future commercial and agent platform direction without implementing cloud services, billing, hosted review, API keys, or secrets.
- Document the product habit around `pkgwhy precheck`, `pkgwhy pip install`, and `pkgwhy agent precheck`.
- Document future tiers for the free local CLI, Pro local policy packs, team review dashboard, hosted package review cache, shared organization policy, and agent install gateway.
- Add explicit hosted-review boundaries so the current local CLI does not imply active cloud review or definitive malware detection.
- Add tests that keep the commercial platform design doc future-only and boundary-aware.
- Harden precheck and pip-gate follow-up review items: direct-reference handling, hash-locked requirements parsing, PyPI specifier release selection, Python 3.11-compatible tar extraction, private pip decision log paths/permissions, and CI pyproject gate coverage.
- Harden second-pass review items: sanitized artifact URLs, stable-release preference for PyPI specifiers, safer keep-artifact failure handling, advisory-mode CI audit behavior, quarantine CLI coverage, and stricter pip requirements snapshot boundaries.

## 1.4.0 - 2026-06-30

- Add local registry trust states: `trusted`, `reviewed`, `quarantined`, `blocked`, and `unknown`.
- Add trust-state storage to registry index entries and include trust state in tool judgement JSON and human output.
- Add `pkgwhy registry trust <tool>`, `pkgwhy registry review <tool>`, `pkgwhy registry quarantine <tool>`, `pkgwhy registry block <tool>`, and `pkgwhy registry blocked`.
- Enforce registry trust state in the local runner policy: `quarantined` and `blocked` tools are refused before execution.
- Keep newly published local tools at `unknown` trust until a human marks them.
- Keep tool lock/verify and registry export/import deferred rather than inventing incomplete trust guarantees.

## 1.3.0 - 2026-06-30

- Add a reusable GitHub Actions package-gate template at `examples/github-actions/pkgwhy-package-gate.yml`.
- Document CI advisory, strict, and agent modes in `docs/ci-templates.md`.
- The CI template installs `pkgwhy`, runs requirements precheck, emits JSON and Markdown audit reports, optionally runs agent precheck, uploads reports, and fails only in strict or agent mode.
- Keep CI package-gate usage local and secret-free by default; no cloud service, hosted review, billing, or credentials are required.
- Add static validation tests for the CI template and documentation boundaries.

## 1.2.0 - 2026-06-30

- Add `pkgwhy pip install <package>` as a local pip install gate over `pkgwhy precheck`.
- Add `pkgwhy pip install -r requirements.txt` for requirements-file gate checks before pip is invoked.
- Add schema-versioned `pkgwhy.pip_install_gate.v1` JSON with precheck decision, gate exit code, pip invocation status, override status, warnings, reasons, and embedded precheck output.
- Add `--policy strict`, `--dry-run`, `--override-review`, `--override-block`, and `--override-reason` for explicit install-gate workflows.
- Add best-effort compact local pip gate decision logs that omit full precheck evidence.
- Keep tests deterministic by using fake pip runners and dry-run paths; tests do not install arbitrary public packages.
- Keep the pip gate conservative: pip is called only after precheck allows it or an explicit override is used, and unavailable or incomplete precheck evidence exits without invoking pip.

## 1.1.0 - 2026-06-30

- Add top-level `pkgwhy precheck` as a local pre-install package gate for humans, CI, and agents.
- Add schema-versioned `pkgwhy.precheck.v1` JSON for single package requirements, including decision, risk, confidence, evidence summaries, vulnerability/provenance/typosquat/static summaries, and embedded package judgement.
- Add schema-versioned `pkgwhy.precheck_batch.v1` JSON for `pkgwhy precheck -r requirements.txt` and `pkgwhy precheck pyproject.toml`.
- Add explicit `--download-artifacts` support that queries PyPI, downloads one wheel or source artifact to a temporary review directory, verifies SHA-256 when PyPI metadata provides it, extracts safely, statically inspects files, and deletes temporary files unless `--keep-artifacts` is set.
- Add optional `--pypi`, `--osv`, and local `--vulnerability-file` enrichment boundaries to precheck without enabling network by default.
- Add `--enforce-exit-code` for gate usage while keeping default JSON and human precheck commands easy to inspect interactively.
- Keep precheck static-first: it does not install, import, or execute inspected package code.

## 1.0.0 - 2026-06-30

- Promote the `1.0.0rc1` release-candidate surface to the final 1.0.0 tracked codebase after local release-prep review.
- Freeze the 1.0.0 feature surface for package intelligence, static rule evidence, vulnerability/provenance decision support, agent policy JSON, local registry/runner safety, and release-process documentation.
- Keep dynamic analysis explicitly experimental and outside the stable security decision surface for this release.
- Align README, SECURITY, package metadata, and version metadata for final local `1.0.0` validation.
- Harden release validation with artifact trace scanning, cache metadata validation, Markdown audit warnings, hermetic JSON snapshots, and exact rule catalog membership tests.
- Align final release wording and package classifier for local 1.0.0 hardening.
- Harden final review checks for offline-first documentation, trace path matching, dynamic boundary wording, Markdown escaping, static corpus import traps, and rule-category ordering.

## 0.9.5a0 - Unreleased pre-alpha

- Add release checklist, versioning policy, threat model, and production-readiness blocker documentation.
- Improve public responsible disclosure guidance without configuring external services or secrets.
- Link release/process documentation from README, SECURITY, and CONTRIBUTING.
- Add CI CLI smoke checks and public trace hygiene scanning without publishing secrets or deployment steps.
- Align local package metadata for the `0.9.5a0` release/process hardening candidate.

## 0.9.0a0 - Unreleased pre-alpha

- Keep dynamic analysis experimental for this release, with no production sandboxing claim.
- Keep `pkgwhy dynamic inspect` as a safe-fail CLI skeleton that refuses host execution of unknown package code and does not invoke Docker or run containers.
- Add tests that assert the dynamic result warnings and limitations carry the explicit experimental boundary.
- Align README, SECURITY, CLI help, and local package metadata for the `0.9.0a0` dynamic-analysis boundary.

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
- Document that results are static evidence and decision support, not proof of package safety or malware certainty.

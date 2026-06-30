# Security Policy

## Supported Status

`pkgwhy` 1.0.0 includes static evidence hardening, vulnerability/provenance foundations, static rule corpus/schema hardening, release/process hardening, a safe-fail experimental dynamic command skeleton, agent policy foundations, and local registry/runner hardening. It is not a production malware scanner and should not be treated as a definitive malware detector or full sandbox.

## Reporting Security Issues

For non-sensitive security bugs or documentation issues, use GitHub Issues:

<https://github.com/devlukeg/pkgwhy/issues>

For sensitive security reports, use GitHub private vulnerability reporting if it is enabled for the public repository. If it is not enabled, contact the maintainer privately through the contact channel listed on the project or repository profile before sharing exploit details.

Sensitive details should be reported privately. Public issues are appropriate for non-sensitive coordination only.

Public issues should not include secrets, private package contents, or credentials.

## Security Model

`pkgwhy` uses static, metadata-first inspection. Package inspection reads metadata, files, text, and AST without importing or executing inspected package code.

Capability analysis reports static signals such as API references, package files, and entry points. These signals are not proof of runtime behavior, intent, or maliciousness.

Static rule evidence can include rule IDs, severity, confidence, file paths, line numbers, symbols, and false-positive notes where available. URL/domain references, native extensions, WASM files, minified JavaScript, source-map references, and credential-like names are review evidence only. They are not proof that code connects to a network, contains a real secret, or is malicious.

Credential-pattern reporting masks suspicious assignment values before output. `pkgwhy` is not a substitute for dedicated secret-scanning tools in repository and release gates.

Known-vulnerability analysis is source-attributed decision support. Local OSV-like files, explicit OSV.dev queries, and cached OSV responses can be incomplete, stale, unavailable, or missing ecosystem-specific details. A missing vulnerability match does not prove that a package has no vulnerabilities.

Provenance analysis is currently metadata-derived. Repository, documentation, homepage, release-activity, and source-distribution fields are reported only when available from installed metadata or optional PyPI JSON payloads. Trusted Publishing and attestation verification are not implemented and must be treated as unknown or not implemented.

`pkgwhy run` is a separate local private-tool execution feature. It intentionally executes local private tool code only after resolving a valid local registry entry, verifying the stored bundle hash, and applying policy checks. This execution path is separate from package inspection and does not mean package inspection imports or executes inspected package code.

The local runner blocks missing or hash-mismatched bundles, corrupt registry indexes, unsupported entrypoints, declared dependencies, and non-interactive runs that are not allowed by both judgement and manifest policy. It uses a Python virtual environment for dependency isolation only; it does not provide OS-level filesystem, network, process, or user permission sandboxing.

Local registry publishing blocks duplicate owner/name/version records and rejects symlinks in tool bundles. Registry-stored manifest and bundle paths must resolve inside the registry root.

Pre-install package gate commands are decision support. `pkgwhy precheck <package> --json` checks package requirements before installation and can optionally query PyPI/OSV or download artifacts only when explicit flags request that work. Artifact precheck downloads to a temporary review directory, verifies SHA-256 when PyPI metadata provides it, statically inspects files, and deletes temporary files by default. It does not install, import, or execute inspected package code.

Agent policy commands are decision support. `pkgwhy agent precheck <package> --json` applies conservative policy to package judgement JSON and defaults to blocking unknown or high-risk package use in non-interactive mode until a human reviews the evidence. Agent decision logs are local compact summaries, best-effort when the config directory is writable, and intentionally omit full package evidence. They are not a tamper-proof audit system.

Runner warning:

```text
This run uses a Python virtual environment for dependency isolation. It does not fully sandbox operating-system permissions.
```

Dynamic analysis is a separate experimental roadmap area and is not part of the stable security decision surface in this release. Dynamic analysis intentionally executes code, so unknown package code is not run on the host. The current `pkgwhy dynamic inspect` command is a safe-fail skeleton: it reports that no sandbox backend is available or that execution is blocked, and refuses to execute the target. Future dynamic analysis is expected to be opt-in, use a disposable sandbox boundary, disable network access by default, use temporary scratch filesystem access by default, avoid host secrets, and fail safely if the requested sandbox backend is unavailable. Empty process, filesystem, or network event lists should not be treated as proof that no behavior occurred.

## Current Limitations

- No complete vulnerability database coverage, guaranteed advisory freshness, or transitive vulnerability analysis yet.
- OSV.dev lookup is optional and must be explicitly requested. Cached OSV responses are stale fallback data, not freshness guarantees.
- Trusted Publishing and attestation verification are not implemented yet.
- Full source distribution versus wheel comparison is not implemented yet.
- No runner dependency installation yet.
- No tool bundle signing or signature verification yet.
- No tamper-proof audit log, remote attestation, or signed decision record yet.
- No tool-specific agent judgement beyond the current package precheck alias yet.
- No cloud registry, remote pull, hosted review API, or account-based registry auth yet.
- Typosquatting detection is heuristic and conservative. It can miss risky names and can surface false positives.
- Static URL/domain and credential-pattern extraction is heuristic. It can miss references and can surface documentation, examples, tests, or placeholders.
- JavaScript minification and native/WASM files are not automatically malicious, and static analysis cannot fully explain compiled or generated artifacts.
- No OS-level sandboxing or production dynamic sandbox in this release.
- No cloud review or remote evidence lookup in the current release.
- No guarantee that every risky behavior can be detected statically.

## Publishing And Secrets

This repository should not contain PyPI tokens, cloud credentials, registry signing keys, or payment-provider secrets.

See also [Threat Model](docs/threat-model.md), [Release Checklist](docs/release-checklist.md), and [Production Readiness Blockers](docs/production-readiness.md).

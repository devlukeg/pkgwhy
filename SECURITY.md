# Security Policy

## Supported Status

`pkgwhy` is in local release-candidate readiness review for `1.0.0rc1`. The current candidate includes static evidence hardening, vulnerability/provenance hardening, static rule corpus/schema hardening, an explicit dynamic-analysis out-of-scope decision for `1.0.0`, release/process hardening, a safe-fail dynamic command skeleton, agent policy foundations, and local registry/runner hardening. It is not a production security scanner and should not be treated as a definitive malware detector or full sandbox.

## Reporting Security Issues

For non-sensitive security bugs or documentation issues, use GitHub Issues:

<https://github.com/devlukeg/pkgwhy/issues>

For sensitive security reports, use the private channel where you received access to the project until a dedicated security contact is configured.

If GitHub private vulnerability reporting is enabled for the public repository, use that channel for sensitive reports. If it is not enabled, do not disclose sensitive details publicly; use a private maintainer contact channel and include only non-sensitive coordination details in public issues.

Do not include secrets, private package contents, or credentials in public issues.

## Security Model

`pkgwhy` uses static, metadata-first inspection. It must not import or execute inspected package code merely to inspect it.

Capability analysis reports static signals such as API references, package files, and entry points. These signals are not proof of runtime behavior, intent, or maliciousness.

Static rule evidence can include rule IDs, severity, confidence, file paths, line numbers, symbols, and false-positive notes where available. URL/domain references, native extensions, WASM files, minified JavaScript, source-map references, and credential-like names are review evidence only. They are not proof that code connects to a network, contains a real secret, or is malicious.

Credential-pattern reporting masks suspicious assignment values before output. Do not rely on `pkgwhy` as a secret scanner; use dedicated secret-scanning tools for repository and release gates.

Known-vulnerability analysis is source-attributed decision support. Local OSV-like files, explicit OSV.dev queries, and cached OSV responses can be incomplete, stale, unavailable, or missing ecosystem-specific details. A missing vulnerability match does not prove that a package has no vulnerabilities.

Provenance analysis is currently metadata-derived. Repository, documentation, homepage, release-activity, and source-distribution fields are reported only when available from installed metadata or optional PyPI JSON payloads. Trusted Publishing and attestation verification are not implemented and must be treated as unknown or not implemented.

`pkgwhy run` is a separate local private-tool execution feature. It intentionally executes local private tool code only after resolving a valid local registry entry, verifying the stored bundle hash, and applying policy checks. This execution path is separate from package inspection and must not be treated as evidence that package inspection imports or executes inspected package code.

The local runner blocks missing or hash-mismatched bundles, corrupt registry indexes, unsupported entrypoints, declared dependencies, and non-interactive runs that are not allowed by both judgement and manifest policy. It uses a Python virtual environment for dependency isolation only; it does not provide OS-level filesystem, network, process, or user permission sandboxing.

Local registry publishing blocks duplicate owner/name/version records and rejects symlinks in tool bundles. Registry-stored manifest and bundle paths must resolve inside the registry root.

Agent policy commands are decision support. `pkgwhy agent precheck <package> --json` applies conservative policy to package judgement JSON and defaults to blocking unknown or high-risk package use in non-interactive mode until a human reviews the evidence. Agent decision logs are local compact summaries, best-effort when the config directory is writable, and intentionally omit full package evidence. They are not a tamper-proof audit system.

Runner warning:

```text
This run uses a Python virtual environment for dependency isolation. It does not fully sandbox operating-system permissions.
```

Dynamic analysis is a separate experimental roadmap area and is out of scope for `1.0.0` production security guarantees. Dynamic analysis intentionally executes code and must not run unknown package code on the host. The current `pkgwhy dynamic inspect` command is a safe-fail skeleton: it reports that no sandbox backend is available or that execution is blocked, and refuses to execute the target. Future dynamic analysis must be opt-in, use a disposable sandbox boundary, disable network access by default, use temporary scratch filesystem access by default, avoid host secrets, and fail safely if the requested sandbox backend is unavailable. Empty process, filesystem, or network event lists must not be treated as proof that no behavior occurred.

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
- No OS-level sandboxing or production dynamic sandbox in the `1.0.0` readiness line.
- No cloud review or remote evidence lookup in the current candidate.
- No guarantee that every risky behavior can be detected statically.

## Publishing And Secrets

This repository should not contain PyPI tokens, cloud credentials, registry signing keys, or payment-provider secrets.

See also [Threat Model](docs/threat-model.md), [Release Checklist](docs/release-checklist.md), and [Production Readiness Blockers](docs/production-readiness.md).

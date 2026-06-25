# Security Policy

## Supported Status

`pkgwhy` is currently in local `0.3.0a0` foundation readiness review. It is not a production security scanner and should not be treated as a definitive malware detector.

## Reporting Security Issues

For non-sensitive security bugs or documentation issues, use GitHub Issues:

<https://github.com/devlukeg/pkgwhy/issues>

For sensitive security reports, use the private channel where you received access to the project until a dedicated security contact is configured.

Do not include secrets, private package contents, or credentials in public issues.

## Security Model

`pkgwhy` uses static, metadata-first inspection. It must not import or execute inspected package code merely to inspect it.

Capability analysis reports static signals such as API references, package files, and entry points. These signals are not proof of runtime behavior, intent, or maliciousness.

Known-vulnerability analysis is source-attributed decision support. Local OSV-like files and explicit OSV.dev queries can be incomplete, stale, unavailable, or missing ecosystem-specific details. A missing vulnerability match does not prove that a package has no vulnerabilities.

Provenance analysis is currently metadata-derived. Repository, documentation, homepage, and release-activity fields are reported only when available from installed metadata or optional metadata payloads. Trusted Publishing, attestation verification, and source distribution versus wheel comparison are not implemented and must be treated as unknown or not implemented.

`pkgwhy run` is a separate local private-tool execution feature. It intentionally executes local private tool code only after resolving a valid local registry entry, verifying the stored bundle hash, and applying policy checks. This execution path is separate from package inspection and must not be treated as evidence that package inspection imports or executes inspected package code.

The local runner blocks missing or hash-mismatched bundles, unsupported entrypoints, declared dependencies, and non-interactive runs that are not allowed by both judgement and manifest policy. It uses a Python virtual environment for dependency isolation only; it does not provide OS-level filesystem, network, process, or user permission sandboxing.

Runner warning:

```text
This run uses a Python virtual environment for dependency isolation. It does not fully sandbox operating-system permissions.
```

## Current Limitations

- No complete vulnerability database coverage, guaranteed advisory freshness, or transitive vulnerability analysis yet.
- OSV.dev lookup is optional and must be explicitly requested.
- Trusted Publishing and attestation verification are not implemented yet.
- Source distribution versus wheel comparison is not implemented yet.
- No runner dependency installation yet.
- No tool bundle signing or signature verification yet.
- No cloud registry, remote pull, hosted review API, or account-based registry auth yet.
- Typosquatting detection is heuristic and conservative. It can miss risky names and can surface false positives.
- No OS-level sandboxing.
- No cloud review or remote evidence lookup in the preview.
- No guarantee that every risky behavior can be detected statically.

## Publishing And Secrets

This repository should not contain PyPI tokens, cloud credentials, registry signing keys, or payment-provider secrets.

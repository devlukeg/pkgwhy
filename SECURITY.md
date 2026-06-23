# Security Policy

## Supported Status

`pkgwhy` is currently in local release-candidate readiness review. It is not a production security scanner and should not be treated as a definitive malware detector.

## Reporting Security Issues

For non-sensitive security bugs or documentation issues, use GitHub Issues:

<https://github.com/devlukeg/pkgwhy/issues>

For sensitive security reports, report privately to Luke Gerakiteys through the channel where you received access to the project until a dedicated private security contact is configured.

Do not include secrets, private package contents, or credentials in public issues.

## Security Model

`pkgwhy` uses static, metadata-first inspection. It must not import or execute inspected package code merely to inspect it.

Capability analysis reports static signals such as API references, package files, and entry points. These signals are not proof of runtime behavior, intent, or maliciousness.

`pkgwhy run` is a separate local private-tool execution feature. It intentionally executes local private tool code only after resolving a valid local registry entry, verifying the stored bundle hash, and applying policy checks. This execution path is separate from package inspection and must not be treated as evidence that package inspection imports or executes inspected package code.

The local runner blocks missing or hash-mismatched bundles, unsupported entrypoints, declared dependencies, and non-interactive runs that are not allowed by both judgement and manifest policy. It uses a Python virtual environment for dependency isolation only; it does not provide OS-level filesystem, network, process, or user permission sandboxing.

Runner warning:

```text
This run uses a Python virtual environment for dependency isolation. It does not fully sandbox operating-system permissions.
```

## Current Limitations

- No vulnerability database integration yet.
- No runner dependency installation yet.
- No tool bundle signing or signature verification yet.
- No cloud registry, remote pull, hosted review API, or account-based registry auth yet.
- Typosquatting detection is heuristic and conservative. It can miss risky names and can surface false positives.
- No OS-level sandboxing.
- No cloud review or remote evidence lookup in the preview.
- No guarantee that every risky behavior can be detected statically.

## Publishing And Secrets

This repository should not contain PyPI tokens, cloud credentials, registry signing keys, or payment-provider secrets.

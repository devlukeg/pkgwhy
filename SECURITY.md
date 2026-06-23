# Security Policy

## Supported Status

`pkgwhy` is currently a pre-alpha developer preview. It is not a production security scanner and should not be treated as a definitive malware detector.

## Reporting Security Issues

For non-sensitive security bugs or documentation issues, use GitHub Issues:

<https://github.com/devlukeg/pkgwhy/issues>

For sensitive security reports, report privately to Luke Gerakiteys through the channel where you received access to the project until a dedicated private security contact is configured.

Do not include secrets, private package contents, or credentials in public issues.

## Security Model

`pkgwhy` uses static, metadata-first inspection. It must not import or execute inspected package code merely to inspect it.

Capability analysis reports static signals such as API references, package files, and entry points. These signals are not proof of runtime behavior, intent, or maliciousness.

## Current Limitations

- No vulnerability database integration yet.
- No typosquatting detector yet.
- No OS-level sandboxing.
- No cloud review or remote evidence lookup in the preview.
- No guarantee that every risky behavior can be detected statically.

## Publishing And Secrets

This repository should not contain PyPI tokens, cloud credentials, registry signing keys, or payment-provider secrets.

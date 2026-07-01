# Versioning Policy

`pkgwhy` is in the `1.5.0` release line. Public JSON schemas and rule IDs are compatibility surfaces; incompatible changes require changelog coverage and may require a schema or catalog version bump.

## Package Versions

- Use PEP 440 versions.
- Use `aN` versions for local pre-alpha milestone builds, such as `0.9.0a0`.
- Use `rcN` versions only when the release-candidate checklist has passed locally for that candidate.
- Use final versions only after the full release checklist and artifact validation pass locally.
- Tags and publication happen through the project release process after local validation.

## Milestone Meaning

- `0.9.0a0`: dynamic-analysis decision is explicit. Dynamic analysis is experimental in this release unless a later commit safely implements a sandbox backend.
- `0.9.5a0`: release/process hardening milestone.
- `1.0.0rc1`: prior local release-candidate review candidate, only if the full release-candidate checklist passed locally.
- `1.0.0`: stable release for the current package-intelligence, conservative static security signal, vulnerability/provenance foundation, agent JSON, local registry/runner, and dynamic-analysis safe-fail surface.
- `1.1.0`: local pre-install package gate with metadata-only precheck, requirements/pyproject batch precheck, explicit artifact-download static inspection, and enforceable gate exit codes.
- `1.2.0`: local pip install gate that runs precheck before pip, supports requirements files, strict policy mode, explicit overrides, stable gate exit codes, and compact local decision logs.
- `1.3.0`: reusable GitHub Actions package-gate template with advisory, strict, and agent modes plus report artifact guidance, without requiring cloud services or secrets.
- `1.4.0`: local registry trust states, trust/quarantine/block commands, tool judgement trust output, and runner enforcement for quarantined or blocked private tools.
- `1.5.0`: commercial and agent platform architecture docs for future local policy packs, team review, hosted package review cache, shared organization policy, and agent install gateway without implementing cloud, billing, API keys, or secrets.

## JSON Schemas

JSON schema policy lives in [JSON Schema Compatibility](json-schema-compatibility.md).

In short:

- Additive optional fields may keep the same schema version when existing consumers can ignore them safely.
- Required fields, removed fields, renamed fields, enum meaning changes, or nested shape changes require a schema version bump.
- Schema versions are not reused for incompatible shapes.

## Static Rule IDs

Static rule policy lives in [Static Rule Corpus](static-rule-corpus.md).

Rule IDs should not be renamed, reused for different semantics, or removed silently. Material severity, confidence, category, or output-shape changes need changelog coverage and may require a catalog or output schema version bump.

## Changelog Discipline

Every milestone should document:

- security and truthfulness boundary changes;
- user-facing CLI or JSON contract changes;
- known limitations and out-of-scope features;
- release process or policy changes;
- review fixes that affect product behavior, tests, or documentation.

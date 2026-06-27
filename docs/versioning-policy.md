# Versioning Policy

`pkgwhy` is still pre-`1.0.0`. Public JSON schemas and rule IDs are stability candidates, but breaking changes are still possible before the final `1.0.0` release.

## Package Versions

- Use PEP 440 versions.
- Use `aN` versions for local pre-alpha milestone candidates, such as `0.9.0a0`.
- Use `rcN` versions only when the release-candidate checklist has passed locally for that candidate.
- Do not tag or publish a version without explicit approval.

## Milestone Meaning

- `0.9.0a0`: dynamic-analysis decision is explicit. Dynamic analysis is experimental and out of scope for `1.0.0` production security guarantees unless a later commit safely implements a sandbox backend.
- `0.9.5a0`: release/process hardening candidate.
- `1.0.0rc1`: local release-candidate review candidate, only if the full release-candidate checklist passes locally.

## JSON Schemas

JSON schema policy lives in [JSON Schema Compatibility](json-schema-compatibility.md).

In short:

- Additive optional fields may keep the same schema version when existing consumers can ignore them safely.
- Required fields, removed fields, renamed fields, enum meaning changes, or nested shape changes require a schema version bump.
- A schema version must not be reused for an incompatible shape.

## Static Rule IDs

Static rule policy lives in [Static Rule Corpus](static-rule-corpus.md).

Rule IDs should not be renamed, reused for different semantics, or removed silently. Material severity, confidence, category, or output-shape changes need changelog coverage and may require a catalog or output schema version bump.

## Changelog Discipline

Every milestone candidate should document:

- security and truthfulness boundary changes;
- user-facing CLI or JSON contract changes;
- known limitations and out-of-scope features;
- release process or policy changes;
- review fixes that affect product behavior, tests, or documentation.

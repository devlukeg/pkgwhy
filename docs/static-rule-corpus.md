# Static Rule Corpus

`pkgwhy` static rules are conservative decision-support signals. They are not proof that a package is safe, unsafe, malicious, or benign.

The current rule catalog is versioned as:

```text
pkgwhy.static_rule_catalog.v1
```

Rule evidence appears inside package judgement JSON and audit JSON. Each rule evidence item includes:

- `rule_id`
- `name`
- `category`
- `severity`
- `confidence`
- `message`
- `evidence`
- `file_path` where feasible
- `line_number` where feasible
- `symbol` where feasible
- `false_positive_note`

## Rule Categories

- `vulnerability`: Source-attributed advisory matches from local OSV-like data or explicit OSV.dev lookups.
- `identity`: Package identity and naming signals, including possible typosquatting similarity.
- `source`: Source availability signals from installed files and metadata.
- `metadata`: Package metadata signals, such as missing license metadata or declarative build metadata.
- `static_analysis`: Python, JavaScript, setup/build-file, URL/domain, credential-pattern, and capability-reference signals found without executing inspected code.
- `binary`: Native extension, executable, and WASM file presence.
- `policy`: Agent or tool policy decisions where the policy layer emits rule evidence.

## Rule Families

- `PKGWHY-VULN-*`: Known-vulnerability advisory matches. Advisory databases can be incomplete; missing matches are not safety evidence.
- `PKGWHY-RISK-*`: Package-level risk signals such as possible typosquatting, missing license metadata, unknown source availability, native code, or static capability signals.
- `PKGWHY-PY-*`: AST-derived Python source signals, including dynamic execution, dynamic imports, deserialisation-risk APIs, encoded payload handling, subprocess/shell execution, environment/secret-like access, package-manager manipulation, unsafe YAML load, and obfuscation-bootstrap markers.
- `PKGWHY-BUILD-*`: Setup/build-file signals from `setup.py`, `setup.cfg`, and `pyproject.toml`.
- `PKGWHY-NET-*`: URL or domain references in source/text files.
- `PKGWHY-CRED-*`: Credential-like assignment patterns with values masked.
- `PKGWHY-JS-*`: JavaScript minification, dynamic execution, encoded payload, obfuscation-like, and source-map signals.
- `PKGWHY-BIN-*`: Native extension/library, WASM, and native executable file signals.

## Corpus Strategy

The `0.8.0` corpus hardening target uses controlled fixtures only. Fixtures should be small, local, and synthetic. They must not contain real malware, real credentials, or real vulnerability claims.

Corpus fixtures should cover:

- Known-good examples that should not produce high-risk signals.
- Suspicious package-name examples and legitimate ecosystem-name false-positive controls.
- Python static signals with stable rule IDs, file paths, line numbers, and symbols where feasible.
- JavaScript minification, dynamic execution, encoded payload, obfuscation-like, and source-map examples.
- Native/WASM/shell/build-file evidence examples.
- Vulnerability/provenance examples using controlled local OSV-like and PyPI-like payloads.
- Golden JSON snapshots for stable agent-facing output.

## Compatibility

Rule IDs are pre-alpha stability candidates. A rule ID should not be renamed, reused for a different meaning, or removed silently. If a rule changes shape or semantics in a way that affects agent-facing JSON consumers, update the relevant schema or catalog version and document the change in `CHANGELOG.md`.

Static signals must keep conservative wording:

```text
Static signals are evidence for review, not proof of runtime behavior or intent.
```

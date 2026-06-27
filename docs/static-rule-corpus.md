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

The release-candidate corpus uses controlled fixtures only. Fixtures should be small, local, and synthetic. They must not contain real malware, real credentials, or real vulnerability claims.

The broader corpus roadmap should cover:

- Known-good examples that should not produce high-risk signals.
- Suspicious package-name examples and legitimate ecosystem-name false-positive controls.
- Python static signals with stable rule IDs, file paths, line numbers, and symbols where feasible.
- JavaScript minification, dynamic execution, encoded payload, obfuscation-like, and source-map examples.
- Native/WASM/shell/build-file evidence examples.
- Vulnerability/provenance examples using controlled local OSV-like and PyPI-like payloads.
- Golden JSON snapshots for stable agent-facing output.

See [JSON Schema Compatibility](json-schema-compatibility.md) for the snapshot and schema-versioning policy.

## Current Fixture Coverage

The current local corpus includes:

- Python static-signal fixtures for dynamic execution, dynamic imports, deserialisation-risk APIs, encoded payload handling, subprocess and package-manager use, environment access, URL/domain extraction, and credential masking.
- JavaScript fixtures for minification, dynamic execution, base64 decode references, obfuscation-like patterns, source-map references, and call-like false-positive controls.
- Native, executable, WASM, shell-script, `setup.py`, `setup.cfg`, and `pyproject.toml` build-file fixtures.
- Golden JSON snapshots for package judgement, audit, agent package precheck, and local private-tool judgement output.

These fixtures are regression inputs. They are not malware samples, real advisory data, real credentials, or proof that the same signal is unsafe in a real package.

## Compatibility

Rule IDs are release-candidate compatibility candidates. A rule ID should not be renamed, reused for a different meaning, or removed silently. If a rule changes shape or semantics in a way that affects agent-facing JSON consumers, update the relevant schema or catalog version and document the change in `CHANGELOG.md`.

Static signals must keep conservative wording:

```text
Static signals are evidence for review, not proof of runtime behavior or intent.
```

## Rule ID Lifecycle

- New rules should use the next unused ID in the matching family.
- A rule ID must keep the same broad meaning once it appears in package judgement JSON.
- If a rule is replaced, leave an explicit changelog note and add a compatibility test for the replacement.
- If severity, confidence, or category changes materially, update documentation and consider whether the static rule catalog version or output schema version must change.
- Rule IDs should be tested through `tests/test_risk_rules.py` and corpus fixtures when a controlled fixture can exercise the rule safely.

## Evidence Location Policy

Rule evidence should include `file_path`, `line_number`, and `symbol` when the scanner can derive them without executing inspected code. Some evidence is package-level or metadata-level, so those fields can be `null`. Examples include native binary presence, missing installed files, and some source-availability signals.

When a scanner reports a line number, tests should prefer controlled fixtures with stable line numbers. When a line number is not feasible, tests should assert the explicit `null` shape rather than fabricating a location.

## False Positives

Static rules intentionally favor reviewable signals over certainty. Common false-positive cases include:

- legitimate plugin systems using dynamic imports;
- build tools or CLI wrappers using subprocess APIs;
- data tools using base64, compression, or deserialisation APIs with trusted inputs;
- documentation, tests, or examples containing URLs, token-like names, or source-map references;
- legitimate numerical, cryptographic, or performance packages shipping native extensions;
- minified JavaScript distributed as normal browser assets;
- package families that share names with popular projects, such as stubs, plugins, integrations, or extensions.

Rule output should include `false_positive_note` where possible so human and agent consumers understand why the signal needs review.

## False Negatives

Static analysis can miss risky behavior. Current known gaps include:

- generated code or compressed assets that are not readable by the scanner;
- behavior hidden in native binaries, WASM, or external services;
- dynamically constructed imports, function names, URLs, commands, or credential references;
- code paths only observable during installation or runtime;
- incomplete installed metadata or distribution file lists;
- missing, stale, or unavailable vulnerability and provenance sources.

No match, no warning, or an empty event list must not be interpreted as proof that a package is safe.

## Local Validation

Useful focused checks for this corpus:

```bash
.venv/bin/python -m pytest tests/test_risk_rules.py tests/test_static_rule_corpus.py tests/test_json_snapshots.py
git diff --check
```

Full release-readiness checks are broader and should include the full test suite, CLI smoke checks, build checks, and public trace scans before any public release decision.

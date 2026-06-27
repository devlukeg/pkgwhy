# Threat Model

`pkgwhy` is a supply-chain security decision-support tool. It reports evidence and risk signals; it does not prove that a package is safe or malicious.

## Assets

- Developer workstations and Python environments.
- AI-agent workflows that may install, inspect, or execute tools.
- Local private tool registries and their manifests, bundles, hashes, and logs.
- Agent-readable JSON decisions consumed by automation.
- User credentials, environment variables, source code, and local project files.

## Trust Boundaries

- Static package inspection reads installed metadata, package files, AST, text patterns, lockfiles, manifests, and optional source-attributed online metadata.
- `pkgwhy run` is explicit execution of local private registry tools after registry, hash, manifest, and policy checks.
- Dynamic analysis is experimental and out of scope for `1.0.0` production security guarantees. It must not run unknown package code on the host.
- Optional OSV.dev and PyPI lookups cross the network only when explicitly requested.

## In-Scope Threats

- Typosquatting or confusing package names.
- Missing, weak, or inconsistent package metadata.
- Unknown source availability or unreadable installed artifacts.
- Static references to filesystem, network, subprocess, shell, dynamic execution, deserialisation, credential-like values, package-manager manipulation, native binaries, WASM, JavaScript, and build-time scripts.
- Known vulnerability matches from source-attributed advisory data.
- Conservative provenance/source-trust gaps from installed metadata or optional PyPI JSON.
- Local registry corruption, path traversal, unsafe symlinks, duplicate tool versions, missing bundles, hash mismatch, and unsupported tool entrypoints.
- Non-interactive agent use of unknown, high-risk, or blocked package/tool decisions.

## Out-Of-Scope Or Not Implemented

- Definitive malware detection.
- Full OS sandboxing.
- Production dynamic analysis for arbitrary packages.
- Complete vulnerability database coverage or guaranteed advisory freshness.
- Transitive vulnerability analysis.
- Trusted Publishing verification.
- Attestation verification.
- Full source distribution versus wheel diffing.
- Tool bundle signing and signature verification.
- Tamper-proof or remote audit logs.
- Cloud registry backends, hosted review APIs, accounts, billing, or remote policy enforcement.

## Safety Properties

- Package inspection must not import or execute inspected package code.
- Missing vulnerability matches must not be described as safety evidence.
- Empty dynamic event lists must not be described as proof that no behavior occurred.
- Static signals must be described as review evidence, not proof of runtime behavior or intent.
- Unknown or unavailable provenance fields must remain `unknown`, `unavailable`, or `not_implemented`.
- Hash mismatch, unsupported entries, corrupt indexes, and unsafe registry paths must fail closed.
- The local runner warning must remain clear that a Python virtual environment is dependency isolation only, not an OS sandbox.

## Residual Risk

`pkgwhy` can miss risky behavior hidden in generated code, native binaries, WASM, external services, dynamically constructed strings, or unobserved runtime paths. It can also surface false positives in documentation, tests, examples, plugins, CLI wrappers, minified assets, or legitimate native-extension packages. Human review remains required for high-impact decisions.

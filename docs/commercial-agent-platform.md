# Commercial And Agent Platform Direction

`pkgwhy` is a local-first package decision-support CLI before it is a hosted product. The commercial direction is to make `pkgwhy` the install gate before `pip install` for humans, CI systems, and AI coding agents:

```bash
pkgwhy precheck <package>
pkgwhy pip install <package>
pkgwhy agent precheck <package> --json
```

Core message:

- Before pip install, ask why.
- Stop AI agents from pip-installing mystery code.
- Treat `pkgwhy` output as decision support, not proof that code is safe or malicious.

This document is architecture and roadmap only. It does not configure a hosted service, billing system, API key, cloud registry, remote review backend, or secrets.

## Local Free CLI

The free local CLI remains the foundation:

- offline-first installed package inspection;
- metadata, manifest, lockfile, and source-file review;
- static capability and readability signals;
- local vulnerability/provenance enrichment when configured;
- `precheck` before installation;
- `pip install` gate over precheck;
- agent-readable JSON and conservative exit codes;
- local private-tool registry and runner;
- local trust labels for private tools.

The local CLI should keep working without a network connection, hosted account, API key, or model provider.

## Pro Local Policy Packs

Future Pro policy packs may add stronger local policy configuration while keeping enforcement on the user's machine:

- organization-ready deny and allow rules;
- curated trusted package baselines;
- stricter agent install policies;
- saved review profiles for common environments;
- local report signing when signing support exists;
- richer local audit history.

Policy packs must not pretend to provide malware certainty or full sandboxing. They should make review decisions more consistent and easier to enforce.

## Team And Cloud Review Dashboard

A future team dashboard may coordinate package reviews across users and repositories:

- review queues for package requests;
- shared decisions with expiry dates;
- links to package evidence and local CLI JSON;
- policy exceptions with named approvers;
- historical review records;
- team-level policy distribution.

This is not implemented in the current release. The current repository contains no hosted service, account system, payment flow, or remote review API.

## Hosted Package Review Cache

A future hosted cache may store source-grounded package review evidence so teams and agents do not repeat the same lookup work:

- package metadata snapshots;
- artifact hashes and static inspection summaries;
- known vulnerability source snapshots;
- provenance and repository metadata snapshots;
- review freshness timestamps;
- privacy controls for private package names and internal decisions.

Hosted cache output should be source-attributed and freshness-aware. Missing hosted evidence must not be treated as proof that a package is safe.

## Shared Organization Policy

Shared policy should make agent behavior predictable:

- block raw public installs by default where required;
- require `pkgwhy precheck` or `pkgwhy pip install`;
- allow trusted internal packages;
- quarantine packages under review;
- block known-bad or policy-disallowed packages;
- require explicit human override reasons.

Policy enforcement should remain conservative. A policy decision can block or require review; it should not claim that a package is definitively safe.

## Agent Install Gateway

The agent install gateway is the commercial platform boundary for AI coding agents. Its job is to turn a package install request into a reviewable decision:

1. Agent requests a package install.
2. Gateway runs or requires `pkgwhy precheck`.
3. Policy decides allow, caution, review, sandbox-only, or block.
4. Allowed installs go through `pkgwhy pip install` or a controlled package source.
5. Review-required and blocked installs return structured JSON for the agent.
6. Human overrides require explicit reason logging.

The local implementation today is `pkgwhy agent precheck` plus `pkgwhy pip install`. A hosted gateway is future work and must not silently install unknown public packages.

## MCP And Agent Gateway Design

A future MCP or agent gateway can expose a small, explicit tool surface:

- `precheck_package(package_spec, policy_mode)`;
- `pip_install_package(package_spec, policy_mode, override_reason)`;
- `explain_decision(review_id)`;
- `list_policy()`;
- `request_human_review(package_spec, evidence)`;
- `record_override(review_id, reason)`.

The gateway should return schema-versioned JSON, avoid executing inspected package code, and fail closed when data is unavailable. It should not expose a raw unrestricted package-install tool.

## Hosted Review Boundaries

Hosted review is future only in this release:

- no cloud service is configured;
- no billing provider is configured;
- no API keys are required;
- no secrets are stored;
- no package names or review data are uploaded by the local CLI unless a future explicit feature says so;
- no cloud result is fabricated;
- no hosted decision is treated as definitive malware detection.

## Roadmap Tiers

Planned product tiers are design targets, not active billing:

- Free local CLI: precheck, pip gate, local JSON, local registry, and local trust labels.
- Pro local policy packs: stricter local rules, saved profiles, local reports, and team-ready defaults.
- Team review dashboard: shared package decisions, approvals, policy exceptions, and review history.
- Hosted package review cache: source-grounded cached package evidence with freshness and privacy controls.
- Agent install gateway: controlled package installation boundary for AI agents.

The next engineering step is to deepen local policy and registry trust before any hosted review or commercial account system is built.

# Dynamic Sandbox Design

Status: experimental and not part of the stable security decision surface in this release.

`pkgwhy` is static and metadata-first by default. Dynamic analysis is different: it intentionally executes code, so it changes the trust and safety boundary. This document defines the safety constraints for any future dynamic analysis work.

## Current State

Dynamic package analysis is not implemented for arbitrary packages.

There is no production malware sandbox, no arbitrary package execution, no dynamic package installation, and no claim of full operating-system sandboxing. Static inspection remains the default package review path.

In this release, dynamic analysis remains experimental. The CLI skeleton remains available to expose the intended JSON shape and safety boundary, and it fails closed rather than running unknown code.

The current CLI surface is a safe-fail skeleton:

```bash
pkgwhy dynamic --help
pkgwhy dynamic inspect --help
pkgwhy dynamic inspect <target> --container --network off
```

Until a sandbox backend exists, `pkgwhy dynamic inspect` refuses to execute the target and reports that the backend is unavailable or blocked. It does not fall back to host execution.

`pkgwhy run` is a separate local private-tool execution path. It resolves tools from a configured local registry and verifies bundle hashes before running them in a Python virtual environment. A virtual environment is dependency isolation only; it is not an operating-system sandbox.

## Separation Of Modes

`pkgwhy` has three distinct execution and inspection modes:

- Static package inspection: reads metadata, files, AST, and text patterns without importing or executing inspected package code.
- Local private-tool execution: runs local registry tools through `pkgwhy run` after local registry, hash, manifest, and policy checks.
- Dynamic sandbox analysis: future opt-in analysis that may execute code only inside a disposable sandbox boundary.

These modes stay separate in commands, docs, result models, and tests.

## Threat Model

Dynamic analysis assumes inspected code may try to:

- read host files, environment variables, credentials, SSH keys, browser profiles, package indexes, or cloud metadata;
- write or delete files outside the analysis workspace;
- start subprocesses, shells, daemons, schedulers, or long-running child processes;
- access the network, DNS, package registries, or local services;
- install more packages or mutate the interpreter environment;
- evade analysis with time delays, platform checks, process checks, or anti-debugging behavior;
- consume excessive CPU, memory, disk, file descriptors, or process slots.

The design goal is to collect bounded behavior evidence, not to prove that code is safe or malicious.

## Safety Principles

Dynamic analysis is designed to be:

- opt-in only;
- disabled by default;
- unavailable for unknown package code unless a sandbox backend is explicitly selected and available;
- network-off by default;
- run in a temporary scratch filesystem by default;
- run without host secrets or inherited project credentials;
- bounded by time, process, memory, disk, and output limits where the backend supports them;
- explicit about unsupported monitoring and incomplete evidence;
- conservative in language and decisions.

If a required sandbox backend is unavailable, the command fails safely with a clear result. It does not silently fall back to host execution.

## Future Container Boundary

If dynamic analysis is revisited after `1.0.0`, the preferred backend is a disposable container or equivalent isolated environment with:

- a fresh filesystem per run;
- no mounted home directory by default;
- no mounted repository by default except an explicit read-only fixture or artifact input;
- no network by default;
- no host environment variables except a minimal allowlist;
- resource limits;
- non-root user where practical;
- process, filesystem, and network event collection where supported;
- automatic cleanup after the run.

Docker may be one backend, but the CLI does not require Docker for static inspection or normal package judgement.

The current `--container` path checks only whether a `docker` executable exists. It does not invoke Docker, start a container, mount files, install packages, or execute target code.

## Event Model Goals

Future dynamic result JSON should distinguish observed events from unavailable telemetry:

- schema version: `pkgwhy.dynamic_analysis.v1`;
- target and mode;
- sandbox backend;
- network mode;
- filesystem mode;
- status and decision;
- process events: started process, command, exit code, duration, resource limits reached;
- filesystem events: created, modified, deleted, or read paths inside the scratch workspace where observable;
- network events: attempted DNS, connect, or HTTP destinations where observable;
- warnings: unsupported monitors, backend limitations, timeout, blocked network, blocked host execution;
- limitations: what was not observed or could not be monitored.

Empty event lists only mean the selected backend did not record events. They should not be interpreted as proof that no behavior occurred.

## Controlled Fixtures

Dynamic-analysis tests use controlled local fixtures created specifically for `pkgwhy` tests. Fixture execution does not install packages, import arbitrary installed packages, access host secrets, or use the network.

Controlled fixture execution is not evidence that arbitrary package execution is safe.

The current controlled fixture helper is for test coverage only. It requires a fixture path under a caller-provided fixture root, runs with a minimal environment, uses a caller-provided scratch working directory, records the fixture process exit code and scratch file creations/modifications, and does not collect network telemetry. It is not exposed as arbitrary package execution.

## Current Limitations

- No arbitrary PyPI package execution.
- No dynamic import or CLI execution of unknown packages.
- No package installation inside a dynamic run unless a later backend explicitly supports isolated install capture.
- No network-enabled analysis by default.
- No host-home or project-wide filesystem access.
- No production malware-detection claim.
- No claim of full sandboxing.

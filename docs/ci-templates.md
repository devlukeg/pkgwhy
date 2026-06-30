# CI Templates

`pkgwhy` can run as a local CI package gate without a cloud service, API key, or secret.

The reusable GitHub Actions template is:

```text
examples/github-actions/pkgwhy-package-gate.yml
```

Copy it into a repository as `.github/workflows/pkgwhy-package-gate.yml` and choose a mode with `PKGWHY_MODE`.

## Modes

- `advisory`: produce reports and never fail the job.
- `strict`: fail when `pkgwhy precheck -r requirements.txt --enforce-exit-code` returns review, block, or unavailable-evidence exit codes.
- `agent`: use the same dependency-file gate as strict mode and optionally run `pkgwhy agent precheck "$PKGWHY_AGENT_PACKAGE" --json`.

## Reports

The template writes:

- `pkgwhy-reports/precheck.json`
- `pkgwhy-reports/audit.json`
- `pkgwhy-reports/audit.md`
- `pkgwhy-reports/agent-precheck.json` when `PKGWHY_MODE=agent` and `PKGWHY_AGENT_PACKAGE` is set.

The template uploads those reports with `actions/upload-artifact`.

## Advisory Mode

Use advisory mode while introducing the gate:

```yaml
env:
  PKGWHY_MODE: advisory
```

This mode is report-only. It does not claim packages are safe and does not block a pull request.

## Strict Mode

Use strict mode when dependency changes should be blocked until precheck allows them:

```yaml
env:
  PKGWHY_MODE: strict
```

Strict mode uses the precheck exit code:

- `0`: allow.
- `1`: review or caution.
- `2`: block or sandbox-only.
- `4`: requested evidence was unavailable or incomplete.

Any non-zero precheck exit fails the job.

## Agent Mode

Use agent mode for repositories where automated agents should not install dependencies without a precheck:

```yaml
env:
  PKGWHY_MODE: agent
  PKGWHY_AGENT_PACKAGE: typer
```

Agent mode is still local decision support. It does not prove package safety, run a hosted review, or sandbox pip.

## Boundaries

- No secrets are required for basic use.
- No hosted `pkgwhy` service is contacted.
- OSV.dev or PyPI lookups happen only if you add explicit flags to the template.
- Static analysis signals are evidence for review, not proof of malicious or safe behavior.
- `pkgwhy pip install` should be used instead of raw `pip install` when install policy is required.

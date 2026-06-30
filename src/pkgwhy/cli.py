from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from pkgwhy.agent.judge import inspect_installed_package, judge_installed_package
from pkgwhy.core.constants import CAPABILITY_EXPOSURE_NOTE
from pkgwhy.core.models import (
    AgentPackagePrecheckResult,
    PackageMetadata,
    PrecheckBatchResult,
    PreInstallPackagePrecheckResult,
    RiskRuleEvidence,
    VulnerabilityMatch,
)
from pkgwhy.dependencies.reason import explain_dependency_reason
from pkgwhy.dynamic.analysis import build_unavailable_dynamic_result
from pkgwhy.explanations.explain import explain_package
from pkgwhy.imports.scanner import scan_project_imports
from pkgwhy.metadata.pypi import PyPIMetadataError, fetch_pypi_project, provenance_from_pypi_payload
from pkgwhy.metadata.installed import get_installed_package, list_installed_packages
from pkgwhy.policy.audit_log import write_agent_package_decision_log
from pkgwhy.policy.agent_policy import default_agent_policy, evaluate_package_policy
from pkgwhy.precheck import (
    PrecheckFileError,
    PrecheckTargetError,
    build_package_precheck,
    build_pyproject_precheck,
    build_requirements_precheck,
)
from pkgwhy.registry.local import add_registry, init_local_registry, list_registries, use_registry
from pkgwhy.registry.publish import publish_local_tool
from pkgwhy.registry.run import RUNNER_ISOLATION_WARNING, run_local_tool
from pkgwhy.registry.tools import judge_tool
from pkgwhy.reports.audit import build_audit_report, render_audit_markdown
from pkgwhy.typosquat.detector import detect_typosquats
from pkgwhy.vulnerabilities.matching import match_vulnerabilities
from pkgwhy.vulnerabilities.osv import load_osv_records, query_osv_cached

app = typer.Typer(no_args_is_help=True, help="Explain, inspect, judge packages, and run local private tools.")
registry_app = typer.Typer(no_args_is_help=True, help="Manage local private registries.")
tool_app = typer.Typer(no_args_is_help=True, help="Inspect and judge local private tools.")
dynamic_app = typer.Typer(
    no_args_is_help=True,
    help="Experimental dynamic analysis; not part of the stable security decision surface in this release.",
)
agent_app = typer.Typer(no_args_is_help=True, help="Agent-facing policy and package precheck commands.")
app.add_typer(registry_app, name="registry")
app.add_typer(tool_app, name="tool")
app.add_typer(dynamic_app, name="dynamic")
app.add_typer(agent_app, name="agent")
console = Console()


@app.command()
def scan(limit: Annotated[int, typer.Option(help="Maximum packages to display.")] = 25) -> None:
    """Scan installed packages in the active Python environment."""
    if limit <= 0:
        raise typer.BadParameter("limit must be greater than zero")
    packages = list_installed_packages()[:limit]
    table = Table(title="Installed packages")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Summary")
    for package in packages:
        table.add_row(package.identity.name, package.identity.version or "unknown", package.summary or "")
    console.print(table)


@app.command()
def explain(package: str, project_root: Annotated[Path, typer.Option(help="Project root for dependency context.")] = Path(".")) -> None:
    """Explain what an installed package appears to do."""
    metadata = get_installed_package(package)
    dependency_status = dependency_status_for(package, project_root, metadata=metadata)
    explanation = explain_package(metadata, package, dependency_status)
    console.print(f"[bold]{explanation.package}[/bold]")
    if explanation.version:
        console.print(f"Version: {explanation.version}")
    console.print(f"Summary: {explanation.summary}")
    console.print(f"Dependency status: {explanation.dependency_status}")
    console.print(f"Confidence: {explanation.confidence.value}")
    if explanation.common_use_cases:
        console.print("Common use cases:")
        for item in explanation.common_use_cases:
            console.print(f"  - {item}")
    if explanation.common_imports:
        console.print("Common imports:")
        for item in explanation.common_imports:
            console.print(f"  - {item}")
    if explanation.minimal_usage_example:
        console.print("Minimal usage example:")
        console.print(explanation.minimal_usage_example)
    console.print(f"Sources used: {', '.join(explanation.sources_used) or 'none'}")


@app.command()
def why(package: str, project_root: Annotated[Path, typer.Option(help="Project root to inspect.")] = Path(".")) -> None:
    """Explain why a package may be installed in the current project."""
    imports = scan_project_imports(project_root)
    reason = explain_dependency_reason(package, project_root, imports)
    console.print(f"[bold]{package}[/bold]")
    console.print(f"Dependency status: {reason.status.value}")
    if reason.declared_in:
        console.print(f"Declared in: {', '.join(reason.declared_in)}")
    if reason.transitive_via:
        console.print(f"Transitive parent signal: {', '.join(reason.transitive_via)}")
    if reason.lockfiles:
        console.print(f"Lockfile signal: {', '.join(reason.lockfiles)}")
    if reason.imported_by_project:
        console.print("Local import signal: imported by project source.")
    else:
        console.print("Local import signal: no matching top-level import found.")
    console.print("Evidence:")
    for item in reason.evidence:
        console.print(f"  - {item}")


@app.command()
def inspect(package: str) -> None:
    """Inspect installed package metadata and files without importing package code."""
    inspection = inspect_installed_package(package)
    if inspection is None:
        _package_not_found(package)
        raise typer.Exit(1)

    metadata = inspection.metadata
    console.print(f"[bold]{metadata.identity.name}[/bold] {metadata.identity.version or 'unknown'}")
    console.print(f"Summary: {metadata.summary or 'Unavailable from installed metadata.'}")
    console.print(f"License: {metadata.license or 'Unknown from installed metadata.'}")
    console.print(f"Source availability: {inspection.source_availability.value}")
    console.print(f"Readability: {inspection.readability.value}")
    console.print(f"Installed size: {inspection.size.total_bytes} bytes across {inspection.size.file_count} files")
    console.print("Runtime capability exposure:")
    console.print(f"  {CAPABILITY_EXPOSURE_NOTE}")
    if inspection.detected_capabilities:
        console.print("Detected capability signals:")
        for capability in inspection.detected_capabilities:
            console.print(f"  - {capability}")
    if inspection.warnings:
        console.print("Warnings:")
        for warning in inspection.warnings:
            console.print(f"  - {warning}")
    _print_rule_evidence(inspection.rule_evidence)
    if inspection.size.largest_files:
        console.print("Largest files:")
        for item in inspection.size.largest_files:
            console.print(f"  - {item.path}: {item.size_bytes} bytes")


@app.command()
def judge(package: str, as_json: Annotated[bool, typer.Option("--json", help="Emit stable JSON for agents.")] = False) -> None:
    """Produce a conservative package judgement."""
    judgement = judge_installed_package(package)
    if as_json:
        print(json.dumps(judgement.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    console.print(f"[bold]{judgement.package}[/bold]")
    console.print(f"Decision: {judgement.decision.value}")
    console.print(f"Risk level: {judgement.risk_level.value}")
    console.print(f"Confidence: {judgement.confidence.value}")
    console.print(f"Recommendation: {judgement.recommendation}")
    if judgement.warnings:
        console.print("Warnings:")
        for warning in judgement.warnings:
            console.print(f"  - {warning}")
    _print_rule_evidence(judgement.risk_rules)


@app.command()
def risk(package: str, as_json: Annotated[bool, typer.Option("--json", help="Emit JSON risk report.")] = False) -> None:
    """Show conservative risk judgement for a package."""
    judgement = judge_installed_package(package)
    if as_json:
        print(json.dumps(judgement.model_dump(mode="json"), indent=2, sort_keys=True))
        return

    console.print(f"[bold]{judgement.package}[/bold]")
    console.print(f"Risk level: {judgement.risk_level.value}")
    console.print(f"Decision: {judgement.decision.value}")
    console.print(f"Confidence: {judgement.confidence.value}")
    console.print(f"Source availability: {judgement.source_availability.value}")
    console.print(f"Installed size: {judgement.installed_size_bytes} bytes")
    console.print(f"Recommendation: {judgement.recommendation}")
    if judgement.detected_capabilities:
        console.print("Detected capability signals:")
        for capability in judgement.detected_capabilities:
            console.print(f"  - {capability}")
    if judgement.warnings:
        console.print("Warnings:")
        for warning in judgement.warnings:
            console.print(f"  - {warning}")
    _print_rule_evidence(judgement.risk_rules)
    if judgement.evidence:
        if len(judgement.evidence) > 10:
            console.print(f"Evidence (showing first 10 of {len(judgement.evidence)}):")
        else:
            console.print("Evidence:")
        for item in judgement.evidence[:10]:
            console.print(f"  - {item}")


@app.command()
def audit(
    limit: Annotated[int, typer.Option(help="Maximum installed packages to audit.")] = 25,
    as_json: Annotated[bool, typer.Option("--json", help="Emit schema-versioned JSON audit report.")] = False,
    markdown: Annotated[bool, typer.Option("--markdown", help="Emit Markdown audit report.")] = False,
    output: Annotated[Path | None, typer.Option(help="Optional output path for JSON or Markdown reports.")] = None,
    vulnerability_file: Annotated[
        Path | None,
        typer.Option(help="Optional local OSV-like JSON file with vulnerability data. No network is used."),
    ] = None,
    osv: Annotated[
        bool,
        typer.Option("--osv", help="Query OSV.dev for known vulnerabilities. Network is never used unless this is set."),
    ] = False,
    osv_cache_dir: Annotated[
        Path | None,
        typer.Option(help="Optional OSV.dev cache directory. Defaults to the pkgwhy user cache."),
    ] = None,
    pypi: Annotated[
        bool,
        typer.Option("--pypi", help="Query PyPI JSON for provenance metadata. Network is never used unless this is set."),
    ] = False,
) -> None:
    """Audit installed packages with conservative static judgements."""
    if limit <= 0:
        raise typer.BadParameter("limit must be greater than zero")
    if as_json and markdown:
        raise typer.BadParameter("Choose either --json or --markdown, not both")
    if output is not None and not (as_json or markdown):
        raise typer.BadParameter("--output requires --json or --markdown")

    packages = list_installed_packages()[:limit]
    vulnerability_records = []
    audit_warnings: list[str] = []
    if vulnerability_file is not None:
        try:
            vulnerability_records = load_osv_records(vulnerability_file)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc

    judgements = []
    for package in packages:
        package_name = package.identity.name
        package_version = package.identity.version
        matches = match_vulnerabilities(package_name, package_version, vulnerability_records)
        if osv:
            lookup = query_osv_cached(package_name, package_version, cache_dir=osv_cache_dir)
            audit_warnings.extend(lookup.warnings)
            if lookup.cache_status == "stale_cache":
                audit_warnings.append(f"OSV.dev lookup used stale cached data for {package_name}.")
            elif lookup.cache_status == "unavailable":
                audit_warnings.append(f"OSV.dev lookup unavailable for {package_name}; no vulnerability result was inferred.")
            matches.extend(match_vulnerabilities(package_name, package_version, lookup.records))
        matches = _dedupe_vulnerability_matches(matches)
        provenance = None
        if pypi:
            try:
                provenance = provenance_from_pypi_payload(
                    package_name,
                    fetch_pypi_project(package_name),
                    audited_version=package_version,
                )
            except PyPIMetadataError as exc:
                audit_warnings.append(
                    f"PyPI provenance lookup unavailable for {package_name}: {exc}. "
                    "Provenance fields fall back to installed metadata where available."
                )
        judgements.append(
            judge_installed_package(package_name, known_vulnerabilities=matches, provenance=provenance)
        )

    report = build_audit_report(judgements, warnings=audit_warnings)

    if as_json:
        rendered = json.dumps(report, indent=2, sort_keys=True)
        _emit_or_write(rendered, output)
        return
    if markdown:
        rendered = render_audit_markdown(judgements, warnings=audit_warnings)
        _emit_or_write(rendered, output)
        return

    table = Table(title="Package audit")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Risk")
    table.add_column("Decision")
    table.add_column("Vulns")
    table.add_column("Warnings")
    for judgement in judgements:
        table.add_row(
            judgement.package,
            judgement.version or "unknown",
            judgement.risk_level.value,
            judgement.decision.value,
            str(len(judgement.known_vulnerabilities)),
            str(len(judgement.warnings)),
        )
    console.print(table)
    for warning in audit_warnings:
        console.print(f"Warning: {warning}")


@app.command()
def precheck(
    package: Annotated[
        str | None,
        typer.Argument(help="Package requirement or pyproject.toml to check before installation."),
    ] = None,
    requirements: Annotated[
        Path | None,
        typer.Option("-r", "--requirement", help="Requirements file to check before installation."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit schema-versioned precheck JSON.")] = False,
    pypi: Annotated[
        bool,
        typer.Option("--pypi", help="Explicitly query PyPI metadata. Network is never used unless this is set."),
    ] = False,
    osv: Annotated[
        bool,
        typer.Option("--osv", help="Explicitly query OSV.dev. Network is never used unless this is set."),
    ] = False,
    osv_cache_dir: Annotated[
        Path | None,
        typer.Option(help="Optional OSV.dev cache directory. Defaults to the pkgwhy user cache."),
    ] = None,
    vulnerability_file: Annotated[
        Path | None,
        typer.Option(help="Optional local OSV-like JSON file with vulnerability data. No network is used."),
    ] = None,
) -> None:
    """Check a package before installation without installing, importing, or executing it."""
    try:
        if requirements is not None:
            if package is not None:
                raise PrecheckFileError("use either a package target or -r/--requirement, not both")
            result = build_requirements_precheck(
                requirements,
                pypi=pypi,
                osv=osv,
                osv_cache_dir=osv_cache_dir,
                vulnerability_file=vulnerability_file,
            )
        elif package is not None and Path(package).name == "pyproject.toml":
            result = build_pyproject_precheck(
                Path(package),
                pypi=pypi,
                osv=osv,
                osv_cache_dir=osv_cache_dir,
                vulnerability_file=vulnerability_file,
            )
        elif package is not None:
            result = build_package_precheck(
                package,
                pypi=pypi,
                osv=osv,
                osv_cache_dir=osv_cache_dir,
                vulnerability_file=vulnerability_file,
            )
        else:
            raise PrecheckTargetError("precheck requires a package target, pyproject.toml, or -r/--requirement file")
    except (PrecheckTargetError, PrecheckFileError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    if isinstance(result, PrecheckBatchResult):
        _emit_precheck_batch(result, as_json=as_json)
        return
    _emit_precheck_package(result, as_json=as_json)


@app.command()
def typos(packages: Annotated[list[str] | None, typer.Argument(help="Package names to check. Omit to scan installed packages.")] = None) -> None:
    """Detect conservative typosquatting similarity signals."""
    names = packages if packages else [package.identity.name for package in list_installed_packages()]
    candidates = detect_typosquats(names)
    if not candidates:
        console.print("No possible typosquatting signals found.")
        return

    table = Table(title="Possible typosquatting signals")
    table.add_column("Package")
    table.add_column("Possible target")
    table.add_column("Similarity")
    table.add_column("Signals")
    table.add_column("Recommendation")
    for candidate in candidates:
        table.add_row(
            candidate.package,
            candidate.possible_target,
            f"{candidate.similarity:.3f}",
            ", ".join(candidate.signals),
            candidate.recommendation,
        )
    console.print(table)


@app.command()
def publish(path: Annotated[Path, typer.Argument(help="Local .py file or folder with pkgwhy.toml to publish.")]) -> None:
    """Publish a local private tool into the current local registry."""
    try:
        result = publish_local_tool(path)
    except ValueError as exc:
        console.print(str(exc))
        raise typer.Exit(1) from exc

    manifest = result.manifest
    console.print(f"Published {manifest.owner}/{manifest.name} {manifest.version} to registry '{result.registry_name}'")
    console.print(f"Bundle: {result.bundle_path}")
    console.print(f"SHA-256: {result.sha256}")
    console.print("Signature status: not_implemented")


@app.command()
def run(
    reference: Annotated[str, typer.Argument(help="Tool name or owner/name reference from the local registry.")],
    non_interactive: Annotated[
        bool,
        typer.Option("--non-interactive", help="Apply conservative non-interactive tool execution policy."),
    ] = False,
) -> None:
    """Run a hash-verified local private tool from the current local registry."""
    print(RUNNER_ISOLATION_WARNING, file=sys.stderr)
    try:
        result = run_local_tool(reference, non_interactive=non_interactive)
    except ValueError as exc:
        console.print(str(exc))
        raise typer.Exit(1) from exc

    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(result.stderr, end="" if result.stderr.endswith("\n") else "\n")
    console.print(f"Execution log: {result.log_path}")
    raise typer.Exit(result.exit_code)


@agent_app.command("policy")
def agent_policy(as_json: Annotated[bool, typer.Option("--json", help="Emit schema-versioned agent policy JSON.")] = False) -> None:
    """Show conservative default policy for agent package and tool decisions."""
    policy = default_agent_policy()
    if as_json:
        print(json.dumps(policy.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    console.print("[bold]Agent policy[/bold]")
    console.print(f"Schema: {policy.schema_version}")
    console.print(f"Public PyPI allowed by default: {policy.allow_public_pypi}")
    console.print(f"Unpinned dependencies allowed by default: {policy.allow_unpinned_dependencies}")
    console.print(f"Unsigned tools allowed by default: {policy.allow_unsigned_tools}")
    console.print(f"Non-interactive default decision: {policy.non_interactive_default_decision.value}")
    console.print(f"Unknown package decision: {policy.unknown_package_decision.value}")
    console.print(f"Non-interactive unknown package decision: {policy.non_interactive_unknown_package_decision.value}")
    console.print(f"High-risk package decision: {policy.high_risk_package_decision.value}")
    console.print(f"Non-interactive high-risk package decision: {policy.non_interactive_high_risk_package_decision.value}")
    console.print("Policy is decision support; it does not install, import, or execute packages.")


@agent_app.command("precheck")
def agent_precheck(
    package: Annotated[str, typer.Argument(help="Installed package name to judge against agent policy.")],
    as_json: Annotated[bool, typer.Option("--json", help="Emit schema-versioned agent precheck JSON.")] = False,
    non_interactive: Annotated[
        bool,
        typer.Option(
            "--non-interactive/--interactive",
            help="Apply conservative non-interactive agent defaults.",
        ),
    ] = True,
) -> None:
    """Apply conservative agent policy to an installed package judgement."""
    result = _build_agent_package_precheck(package, non_interactive=non_interactive)
    log_path = write_agent_package_decision_log(result)
    _emit_agent_package_precheck(result, as_json=as_json, log_path=log_path)


@agent_app.command("judge")
def agent_judge(
    package: Annotated[str, typer.Argument(help="Installed package name to judge against agent policy.")],
    as_json: Annotated[bool, typer.Option("--json", help="Emit schema-versioned agent judgement JSON.")] = False,
    non_interactive: Annotated[
        bool,
        typer.Option(
            "--non-interactive/--interactive",
            help="Apply conservative non-interactive agent defaults.",
        ),
    ] = True,
) -> None:
    """Alias for package precheck until tool-specific agent judgement is expanded."""
    result = _build_agent_package_precheck(package, non_interactive=non_interactive)
    log_path = write_agent_package_decision_log(result)
    _emit_agent_package_precheck(result, as_json=as_json, log_path=log_path)


@dynamic_app.command("inspect")
def dynamic_inspect(
    target: Annotated[str, typer.Argument(help="Target package or artifact reference to analyze dynamically.")],
    container: Annotated[
        bool,
        typer.Option("--container", help="Require a disposable container backend. Host execution is never used."),
    ] = False,
    network: Annotated[
        str,
        typer.Option("--network", help="Network mode for a future sandbox backend. Only 'off' is accepted currently."),
    ] = "off",
    as_json: Annotated[bool, typer.Option("--json", help="Emit schema-versioned dynamic analysis JSON.")] = False,
) -> None:
    """Experimental dynamic analysis skeleton that fails safely without a backend."""
    result = build_unavailable_dynamic_result(target, container=container, network=network)
    if as_json:
        print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
        raise typer.Exit(1)

    for warning in result.warnings:
        console.print(warning)
    if result.limitations:
        console.print("Limitations:")
        for limitation in result.limitations:
            console.print(f"  - {limitation}")
    console.print(f"Target was not executed: {result.target}")
    raise typer.Exit(1)


@tool_app.command("inspect")
def tool_inspect(reference: Annotated[str, typer.Argument(help="Tool name or owner/name reference.")]) -> None:
    """Inspect a locally published private tool."""
    try:
        judgement = judge_tool(reference)
    except ValueError as exc:
        console.print(str(exc))
        raise typer.Exit(1) from exc

    console.print(f"[bold]{judgement.tool}[/bold] {judgement.version}")
    console.print(f"Description: {judgement.manifest.description}")
    console.print(f"Artifact type: {judgement.manifest.artifact_type.value}")
    console.print(f"Entrypoint: {judgement.manifest.entrypoint}")
    console.print(f"Hash status: {judgement.hash_status.value}")
    console.print(f"Signature status: {judgement.signature_status}")
    console.print(f"Risk level: {judgement.risk_level.value}")
    console.print(f"Decision: {judgement.decision.value}")
    if judgement.declared_permissions:
        console.print("Declared permissions:")
        for permission in judgement.declared_permissions:
            console.print(f"  - {permission}")
    if judgement.warnings:
        console.print("Warnings:")
        for warning in judgement.warnings:
            console.print(f"  - {warning}")


@tool_app.command("judge")
def tool_judge(
    reference: Annotated[str, typer.Argument(help="Tool name or owner/name reference.")],
    as_json: Annotated[bool, typer.Option("--json", help="Emit stable JSON for agents.")] = False,
) -> None:
    """Produce a conservative private tool judgement."""
    try:
        judgement = judge_tool(reference)
    except ValueError as exc:
        console.print(str(exc))
        raise typer.Exit(1) from exc

    if as_json:
        print(json.dumps(judgement.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    console.print(f"[bold]{judgement.tool}[/bold]")
    console.print(f"Decision: {judgement.decision.value}")
    console.print(f"Risk level: {judgement.risk_level.value}")
    console.print(f"Hash status: {judgement.hash_status.value}")
    console.print(f"Recommendation: {judgement.recommendation}")


@registry_app.command("init")
def registry_init(
    path: Annotated[Path, typer.Argument(help="Local registry directory to create or initialize.")],
    name: Annotated[str, typer.Option(help="Registry name to store in local config.")] = "local",
) -> None:
    """Initialize a local private registry directory and select it."""
    entry = init_local_registry(path, name=name)
    console.print(f"Initialized registry '{entry.name}' at {entry.path}")
    console.print(f"Current registry: {entry.name}")


@registry_app.command("add")
def registry_add(
    name: Annotated[str, typer.Argument(help="Registry name to store in local config.")],
    path: Annotated[Path, typer.Argument(help="Existing local registry directory.")],
) -> None:
    """Add an existing local registry directory to config."""
    try:
        entry = add_registry(name, path)
    except ValueError as exc:
        console.print(str(exc))
        raise typer.Exit(1) from exc
    console.print(f"Added registry '{entry.name}' at {entry.path}")
    if not entry.index_exists:
        console.print("Warning: registry index not found. Verify the directory contains 'pkgwhy-registry.json'.")


@registry_app.command("use")
def registry_use(name: Annotated[str, typer.Argument(help="Configured registry name to select.")]) -> None:
    """Select the active local registry."""
    try:
        entry = use_registry(name)
    except ValueError as exc:
        console.print(str(exc))
        raise typer.Exit(1) from exc
    console.print(f"Current registry: {entry.name}")
    console.print(f"Path: {entry.path}")


@registry_app.command("list")
def registry_list() -> None:
    """List configured local registries."""
    entries = list_registries()
    if not entries:
        console.print("No registries configured.")
        return

    table = Table(title="Configured registries")
    table.add_column("Current")
    table.add_column("Name")
    table.add_column("Path")
    table.add_column("Index")
    for entry in entries:
        table.add_row(
            "*" if entry.is_current else "",
            entry.name,
            str(entry.path),
            "present" if entry.index_exists else "missing",
        )
    console.print(table)


def dependency_status_for(
    package: str,
    project_root: Path,
    project_imports: set[str] | None = None,
    metadata: PackageMetadata | None = None,
) -> str:
    reason = explain_dependency_reason(package, project_root, project_imports, metadata)
    return reason.status.value


def _package_not_found(package: str) -> None:
    console.print(f"Package '{package}' is not installed in the active Python environment.")


def _emit_or_write(rendered: str, output: Path | None) -> None:
    if output is None:
        print(rendered, end="" if rendered.endswith("\n") else "\n")
        return
    try:
        output.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        console.print(f"Could not write report to {output}: {exc}")
        raise typer.Exit(1) from exc
    console.print(f"Wrote report to {output}")


def _print_rule_evidence(rules: list[RiskRuleEvidence], limit: int = 8) -> None:
    if not rules:
        return
    selected_rules = sorted(rules, key=_rule_sort_key)[:limit]
    heading = f"Rule evidence (showing first {limit} of {len(rules)}):" if len(rules) > limit else "Rule evidence:"
    console.print(heading)
    for rule in selected_rules:
        location = _format_rule_location(rule)
        location_text = f" at {location}" if location else ""
        console.print(
            f"  - {rule.rule_id} ({rule.severity.value}/{rule.confidence.value}) {rule.name}{location_text}: {rule.message}"
        )


def _rule_sort_key(rule: RiskRuleEvidence) -> tuple[int, str, str]:
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    return severity_order.get(rule.severity.value, 5), rule.rule_id, rule.file_path or ""


def _format_rule_location(rule: RiskRuleEvidence) -> str:
    if rule.file_path and rule.line_number:
        return f"{rule.file_path}:{rule.line_number}"
    if rule.file_path:
        return rule.file_path
    if rule.symbol:
        return rule.symbol
    return ""


def _build_agent_package_precheck(package: str, *, non_interactive: bool) -> AgentPackagePrecheckResult:
    judgement = judge_installed_package(package)
    return evaluate_package_policy(judgement, non_interactive=non_interactive)


def _emit_agent_package_precheck(
    result: AgentPackagePrecheckResult,
    *,
    as_json: bool,
    log_path: Path | None = None,
) -> None:
    if as_json:
        print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    console.print(f"[bold]{result.package}[/bold]")
    console.print(f"Decision: {result.decision.value}")
    console.print(f"Risk level: {result.risk_level.value}")
    console.print(f"Confidence: {result.confidence.value}")
    console.print(f"Policy source: {result.policy_decision_source}")
    console.print(f"Recommendation: {result.recommendation}")
    if log_path is not None:
        console.print(f"Decision log: {log_path}")
    if result.reasons:
        console.print("Policy reasons:")
        for reason in result.reasons:
            console.print(f"  - {reason}")
    if result.warnings:
        console.print("Warnings:")
        for warning in result.warnings:
            console.print(f"  - {warning}")


def _emit_precheck_package(result: PreInstallPackagePrecheckResult, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    console.print(f"[bold]{result.requested}[/bold]")
    console.print("Before pip install, ask why.")
    console.print(f"Decision: {result.decision.value}")
    console.print(f"Risk level: {result.risk_level.value}")
    console.print(f"Confidence: {result.confidence.value}")
    console.print(f"Metadata source: {result.metadata_source}")
    console.print(f"Lookup status: {result.lookup_status}")
    console.print(f"Artifacts downloaded: {str(result.artifacts_downloaded).lower()}")
    console.print(f"Recommendation: {result.recommendation}")
    console.print(f"Vulnerability summary: {result.vulnerability_summary.status}")
    console.print(f"Provenance summary: {result.provenance_summary.status}")
    console.print(f"Typosquat summary: {result.typosquat_summary.status}")
    console.print(f"Static summary: {result.static_summary.status}")
    if result.policy_reasons:
        console.print("Policy reasons:")
        for reason in result.policy_reasons:
            console.print(f"  - {reason}")
    if result.warnings:
        console.print("Warnings:")
        for warning in result.warnings:
            console.print(f"  - {warning}")


def _emit_precheck_batch(result: PrecheckBatchResult, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    console.print(f"[bold]{result.source}[/bold]")
    console.print("Before pip install, ask why.")
    console.print(f"Packages checked: {result.package_count}")
    console.print(f"Decision: {result.decision.value}")
    console.print(f"Risk level: {result.risk_level.value}")
    console.print(f"Confidence: {result.confidence.value}")
    table = Table(title="Precheck results")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Risk")
    table.add_column("Decision")
    table.add_column("Lookup")
    for item in result.results:
        table.add_row(
            item.requested,
            item.version or "unknown",
            item.risk_level.value,
            item.decision.value,
            item.lookup_status,
        )
    console.print(table)
    if result.warnings:
        console.print("Warnings:")
        for warning in result.warnings[:10]:
            console.print(f"  - {warning}")


def _dedupe_vulnerability_matches(matches: list[VulnerabilityMatch]) -> list[VulnerabilityMatch]:
    deduped: dict[str, VulnerabilityMatch] = {}
    for match in matches:
        existing = deduped.get(match.vulnerability_id)
        if existing is None or _vulnerability_match_rank(match) > _vulnerability_match_rank(existing):
            deduped[match.vulnerability_id] = match
    return sorted(deduped.values(), key=lambda item: item.vulnerability_id)


def _vulnerability_match_rank(match: VulnerabilityMatch) -> tuple[int, bool, int, bool, int]:
    severity_order = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MODERATE": 3,
        "MEDIUM": 3,
        "LOW": 2,
    }
    strongest_severity = max((severity_order.get(value.upper(), 1) for value in match.severity), default=0)
    return (
        strongest_severity,
        bool(match.fixed_versions),
        len(match.evidence),
        bool(match.source_url),
        len(match.references),
    )

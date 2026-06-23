from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from pkgwhy.agent.judge import inspect_installed_package, judge_installed_package
from pkgwhy.core.constants import CAPABILITY_EXPOSURE_NOTE
from pkgwhy.core.models import PackageMetadata
from pkgwhy.dependencies.reason import explain_dependency_reason
from pkgwhy.explanations.explain import explain_package
from pkgwhy.imports.scanner import scan_project_imports
from pkgwhy.metadata.installed import get_installed_package, list_installed_packages
from pkgwhy.registry.local import add_registry, init_local_registry, list_registries, use_registry
from pkgwhy.reports.audit import build_audit_report, render_audit_markdown
from pkgwhy.typosquat.detector import detect_typosquats

app = typer.Typer(no_args_is_help=True, help="Explain, inspect, and judge Python packages.")
registry_app = typer.Typer(no_args_is_help=True, help="Manage local private registries.")
app.add_typer(registry_app, name="registry")
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
) -> None:
    """Audit installed packages with conservative static judgements."""
    if limit <= 0:
        raise typer.BadParameter("limit must be greater than zero")
    if as_json and markdown:
        raise typer.BadParameter("Choose either --json or --markdown, not both")
    if output is not None and not (as_json or markdown):
        raise typer.BadParameter("--output requires --json or --markdown")

    packages = list_installed_packages()[:limit]
    names = [package.identity.name for package in packages]
    judgements = [judge_installed_package(name) for name in names]
    report = build_audit_report(judgements)

    if as_json:
        rendered = json.dumps(report, indent=2, sort_keys=True)
        _emit_or_write(rendered, output)
        return
    if markdown:
        rendered = render_audit_markdown(judgements)
        _emit_or_write(rendered, output)
        return

    table = Table(title="Package audit")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Risk")
    table.add_column("Decision")
    table.add_column("Warnings")
    for judgement in judgements:
        table.add_row(
            judgement.package,
            judgement.version or "unknown",
            judgement.risk_level.value,
            judgement.decision.value,
            str(len(judgement.warnings)),
        )
    console.print(table)


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
    output.write_text(rendered, encoding="utf-8")
    console.print(f"Wrote report to {output}")

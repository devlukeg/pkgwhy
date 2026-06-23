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
from pkgwhy.dependencies.graph import transitive_dependencies_for
from pkgwhy.explanations.explain import explain_package
from pkgwhy.imports.scanner import scan_project_imports
from pkgwhy.manifests.pyproject import read_pyproject_dependencies
from pkgwhy.manifests.requirements import read_requirements_dependencies
from pkgwhy.metadata.installed import get_installed_package, list_installed_packages, normalize_package_name
from pkgwhy.typosquat.detector import detect_typosquats

app = typer.Typer(no_args_is_help=True, help="Explain, inspect, and judge Python packages.")
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
    status = dependency_status_for(package, project_root, imports)
    normalized = normalize_package_name(package)
    console.print(f"[bold]{package}[/bold]")
    console.print(f"Dependency status: {status}")
    if normalized.replace("-", "_") in imports:
        console.print("Local import signal: imported by project source.")
    else:
        console.print("Local import signal: no matching top-level import found.")
    console.print("Evidence: pyproject.toml, requirements.txt, and AST import scan where available.")


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


def dependency_status_for(
    package: str,
    project_root: Path,
    project_imports: set[str] | None = None,
    metadata: PackageMetadata | None = None,
) -> str:
    normalized = normalize_package_name(package)
    declared = set()
    declared.update(read_pyproject_dependencies(project_root / "pyproject.toml"))
    declared.update(read_requirements_dependencies(project_root / "requirements.txt"))
    if normalized in declared:
        return "direct"

    if normalized in transitive_dependencies_for(declared):
        return "transitive"

    metadata = metadata if metadata is not None else get_installed_package(package)
    if metadata is None:
        return "not_installed"

    imports = project_imports if project_imports is not None else scan_project_imports(project_root)
    if normalized.replace("-", "_") in imports:
        return "imported_by_project"
    return "unknown"


def _package_not_found(package: str) -> None:
    console.print(f"Package '{package}' is not installed in the active Python environment.")

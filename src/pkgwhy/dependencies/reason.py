from __future__ import annotations

from pathlib import Path

from pkgwhy.core.models import DependencyReason, DependencyStatus, PackageMetadata
from pkgwhy.dependencies.graph import transitive_dependencies_for, transitive_parents_for
from pkgwhy.imports.scanner import scan_project_imports
from pkgwhy.manifests.lockfiles import read_lockfile_dependencies
from pkgwhy.manifests.pyproject import read_pyproject_dependencies
from pkgwhy.manifests.requirements import read_requirements_dependencies
from pkgwhy.metadata.installed import get_installed_package, normalize_package_name


def explain_dependency_reason(
    package: str,
    project_root: Path,
    project_imports: set[str] | None = None,
    metadata: PackageMetadata | None = None,
) -> DependencyReason:
    normalized = normalize_package_name(package)
    pyproject_dependencies = read_pyproject_dependencies(project_root / "pyproject.toml")
    requirements_dependencies = read_requirements_dependencies(project_root / "requirements.txt")
    declared_dependencies = pyproject_dependencies | requirements_dependencies
    declared_in: list[str] = []
    evidence: list[str] = []

    if normalized in pyproject_dependencies:
        declared_in.append("pyproject.toml")
        evidence.append("Package is declared in pyproject.toml.")
    if normalized in requirements_dependencies:
        declared_in.append("requirements.txt")
        evidence.append("Package is declared in requirements.txt.")

    lockfiles = read_lockfile_dependencies(project_root)
    lockfile_hits = sorted(name for name, dependencies in lockfiles.items() if normalized in dependencies)
    for lockfile in lockfile_hits:
        evidence.append(f"Package appears in {lockfile}.")

    transitive_dependencies = transitive_dependencies_for(declared_dependencies)
    transitive_via = sorted(transitive_parents_for(normalized, declared_dependencies))
    if normalized in transitive_dependencies:
        evidence.append("Package is reachable from installed dependency metadata for declared project dependencies.")
        if transitive_via:
            evidence.append(f"Immediate dependency parent signal: {', '.join(transitive_via)}.")

    installed_metadata = metadata if metadata is not None else get_installed_package(package)
    installed = installed_metadata is not None
    if installed:
        evidence.append("Package is installed in the active Python environment.")
    else:
        evidence.append("Package is not installed in the active Python environment.")

    imports = project_imports if project_imports is not None else scan_project_imports(project_root)
    imported_by_project = normalized.replace("-", "_") in imports
    if imported_by_project:
        evidence.append("Package import name appears in local project source.")

    status = DependencyStatus.UNKNOWN
    if declared_in:
        status = DependencyStatus.DIRECT
    elif normalized in transitive_dependencies:
        status = DependencyStatus.TRANSITIVE
    elif imported_by_project:
        status = DependencyStatus.IMPORTED_BY_PROJECT
    elif not installed:
        status = DependencyStatus.NOT_INSTALLED

    return DependencyReason(
        package=package,
        normalized_package=normalized,
        status=status,
        declared_in=declared_in,
        lockfiles=lockfile_hits,
        imported_by_project=imported_by_project,
        installed=installed,
        transitive_via=transitive_via,
        evidence=evidence,
    )

from __future__ import annotations

from pathlib import Path

from pkgwhy.core.models import PackageIdentity, PackageInspection, PackageJudgement, PackageMetadata, VulnerabilityMatch
from pkgwhy.core.models import ReadabilityStatus, SourceAvailability
from pkgwhy.inspection.files import (
    analyze_file_signals,
    distribution_file_paths,
    infer_readability,
    infer_source_availability,
)
from pkgwhy.inspection.python_static import analyze_python_files
from pkgwhy.inspection.size import measure_distribution_size
from pkgwhy.metadata.installed import get_distribution, get_installed_package, normalize_package_name
from pkgwhy.risk.scoring import judge_inspection

MAX_REPORTED_PATHS = 20


def inspect_installed_package(name: str) -> PackageInspection | None:
    metadata = get_installed_package(name)
    dist = get_distribution(name)
    if metadata is None or dist is None:
        return None

    paths = distribution_file_paths(dist)
    size = measure_distribution_size(dist)
    file_analysis = analyze_file_signals(paths, metadata.entry_points)
    python_analysis = analyze_python_files(paths)
    capabilities = sorted(
        set(file_analysis.detected_capabilities)
        | set(python_analysis.detected_capabilities)
    )
    evidence = [
        "Read installed distribution metadata with importlib.metadata.",
        "Measured installed files listed by distribution metadata.",
        f"Statically parsed {python_analysis.files_scanned} Python files with AST.",
        "Did not import or execute inspected package code.",
    ]
    evidence.extend(file_analysis.evidence)
    evidence.extend(python_analysis.evidence)
    rule_evidence = list(python_analysis.rule_evidence)
    warnings: list[str] = []
    warnings.extend(file_analysis.warnings)
    warnings.extend(python_analysis.warnings)
    if not paths:
        warnings.append("Distribution metadata did not expose installed files for static file inspection.")

    return PackageInspection(
        metadata=metadata,
        source_availability=infer_source_availability(paths),
        readability=infer_readability(paths, file_analysis),
        size=size,
        package_paths=[Path(path) for path in paths[:MAX_REPORTED_PATHS]],
        detected_capabilities=capabilities,
        warnings=warnings,
        evidence=evidence,
        rule_evidence=rule_evidence,
        file_analysis=file_analysis,
    )


def judge_installed_package(name: str, known_vulnerabilities: list[VulnerabilityMatch] | None = None) -> PackageJudgement:
    inspection = inspect_installed_package(name)
    if inspection is None:
        metadata = PackageMetadata(
            identity=PackageIdentity(name=name, normalized_name=normalize_package_name(name), version=None),
            metadata_available=False,
        )
        inspection = PackageInspection(
            metadata=metadata,
            source_availability=SourceAvailability.NOT_INSTALLED,
            readability=ReadabilityStatus.NOT_ENOUGH_SOURCE_AVAILABLE,
            size=measure_distribution_size(None),
            package_paths=[],
            detected_capabilities=[],
            warnings=["Package is not installed in the active Python environment."],
            evidence=["Checked active environment metadata without importing package code."],
        )
    return judge_inspection(inspection, known_vulnerabilities=known_vulnerabilities)

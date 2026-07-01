from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import shutil
import shlex
import tarfile
import tempfile
import tomllib
from typing import Any
from urllib import error, parse, request
import zipfile

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import Specifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pkgwhy.agent.judge import inspect_installed_package, judge_installed_package
from pkgwhy.core.models import (
    AgentDecision,
    Confidence,
    FileStaticAnalysis,
    PackageIdentity,
    PackageInspection,
    PackageMetadata,
    PackageProvenance,
    PackageSize,
    PrecheckArtifactSummary,
    PrecheckBatchResult,
    PreInstallPackagePrecheckResult,
    PrecheckSignalSummary,
    ProjectUrls,
    ReadabilityStatus,
    RuleCategory,
    RiskLevel,
    SourceAvailability,
    VulnerabilityMatch,
)
from pkgwhy.inspection.files import analyze_file_signals, infer_readability, infer_source_availability
from pkgwhy.inspection.python_static import analyze_python_files
from pkgwhy.inspection.size import measure_distribution_size
from pkgwhy.metadata.installed import get_installed_package
from pkgwhy.metadata.pypi import PyPIMetadataError, fetch_pypi_project, provenance_from_pypi_payload
from pkgwhy.policy.agent_policy import evaluate_package_policy
from pkgwhy.risk.scoring import judge_inspection
from pkgwhy.typosquat.detector import detect_typosquat
from pkgwhy.vulnerabilities.matching import match_vulnerabilities
from pkgwhy.vulnerabilities.osv import load_osv_records, query_osv_cached

MAX_ARTIFACT_DOWNLOAD_BYTES = 100 * 1024 * 1024
MAX_ARTIFACT_EXTRACTED_BYTES = 250 * 1024 * 1024
MAX_ARTIFACT_FILE_COUNT = 10000


@dataclass(frozen=True)
class ParsedPrecheckTarget:
    requested: str
    package: str
    normalized_package: str
    specifier: str | None
    exact_version: str | None


class PrecheckTargetError(ValueError):
    """Raised when a precheck target is not a supported package requirement."""


class PrecheckFileError(ValueError):
    """Raised when a dependency declaration file cannot be prechecked."""


@dataclass(frozen=True)
class DependencyDeclarations:
    requirements: list[str]
    warnings: list[str]


def build_package_precheck(
    target: str,
    *,
    pypi: bool = False,
    osv: bool = False,
    osv_cache_dir: Path | None = None,
    vulnerability_file: Path | None = None,
    download_artifacts: bool = False,
    keep_artifacts: bool = False,
    artifact_dir: Path | None = None,
) -> PreInstallPackagePrecheckResult:
    """Build a conservative pre-install package gate result without installing code."""

    parsed = parse_precheck_target(target)
    warnings: list[str] = []
    evidence: list[str] = ["Parsed package requirement without installing package code."]
    vulnerability_records = []
    vulnerability_sources: list[str] = []
    metadata_source = "unavailable"
    lookup_status = "offline_metadata_unavailable"
    provenance: PackageProvenance | None = None
    explicitly_requested_pypi = pypi

    if vulnerability_file is not None:
        try:
            vulnerability_records.extend(load_osv_records(vulnerability_file, package_name=parsed.package))
            vulnerability_sources.append(str(vulnerability_file))
        except ValueError as exc:
            raise PrecheckFileError(f"could not load vulnerability file {vulnerability_file}: {exc}") from exc

    installed_metadata = get_installed_package(parsed.package)
    installed_inspection = inspect_installed_package(parsed.package)
    pypi_payload: dict[str, Any] | None = None

    if download_artifacts:
        pypi = True

    if pypi:
        try:
            pypi_payload = fetch_pypi_project(parsed.package)
            metadata_source = "pypi_json"
            lookup_status = "metadata_found"
            if explicitly_requested_pypi:
                evidence.append("Read PyPI project JSON because --pypi was explicitly requested.")
            else:
                evidence.append("Read PyPI project JSON because --download-artifacts requires artifact metadata.")
        except PyPIMetadataError as exc:
            warnings.append(
                f"PyPI metadata lookup unavailable for {parsed.package}: {exc}. "
                "No package safety result was inferred from the failed lookup."
            )
            lookup_status = "online_metadata_unavailable"

    selected_release_version: str | None = None
    if pypi_payload is not None:
        selected_release_version = _select_release_version(pypi_payload, parsed)
    if pypi_payload is not None and selected_release_version is None:
        inspection = _unavailable_inspection(parsed)
        provenance = PackageProvenance(
            package=parsed.normalized_package,
            version=parsed.exact_version,
            metadata_source="pypi_json",
            confidence=Confidence.LOW,
            warnings=[_release_unavailable_warning(parsed)],
            evidence=["Read PyPI project JSON but did not find a release matching the requested specifier."],
        )
        lookup_status = "requested_release_unavailable"
        warnings.append(_release_unavailable_warning(parsed))
        evidence.append("Read PyPI project JSON but did not reuse latest-release metadata for an unmatched specifier.")
    elif pypi_payload is not None:
        inspection = _inspection_from_pypi_payload(parsed, pypi_payload, selected_release_version)
        provenance = provenance_from_pypi_payload(
            parsed.package,
            pypi_payload,
            audited_version=selected_release_version or inspection.metadata.identity.version,
        )
    elif installed_inspection is not None:
        inspection = installed_inspection
        metadata_source = "installed_distribution_metadata"
        lookup_status = "installed_metadata_found"
        evidence.append("Reused installed distribution metadata and static file evidence; no package code was imported.")
        if parsed.exact_version and installed_metadata and installed_metadata.identity.version != parsed.exact_version:
            warnings.append(
                f"Requested version {parsed.exact_version} does not match installed version "
                f"{installed_metadata.identity.version or 'unknown'}; installed-package evidence may not represent the requested release."
            )
    else:
        inspection = _unavailable_inspection(parsed)
        provenance = PackageProvenance(
            package=parsed.normalized_package,
            version=parsed.exact_version,
            metadata_source="unavailable",
            confidence=Confidence.LOW,
            warnings=["No installed or online package metadata was available for provenance review."],
            evidence=["Precheck did not find installed metadata and no successful online metadata lookup was available."],
        )
        warnings.append("Package is not installed and no online metadata lookup was requested or available.")

    version = parsed.exact_version or inspection.metadata.identity.version
    if osv:
        lookup = query_osv_cached(parsed.package, version, cache_dir=osv_cache_dir)
        vulnerability_records.extend(lookup.records)
        vulnerability_sources.append("OSV.dev")
        warnings.extend(lookup.warnings)

    artifact_summary = PrecheckArtifactSummary()
    if download_artifacts:
        if pypi_payload is None:
            artifact_summary = PrecheckArtifactSummary(
                status="unavailable",
                warnings=["Artifact download requires successful PyPI metadata lookup."],
            )
        else:
            artifact_review = _inspect_downloaded_artifact(
                parsed,
                pypi_payload,
                metadata=inspection.metadata,
                keep_artifacts=keep_artifacts,
                artifact_dir=artifact_dir,
            )
            inspection = artifact_review.inspection
            artifact_summary = artifact_review.summary
            warnings.extend(artifact_summary.warnings)
            evidence.extend(artifact_summary.evidence)

    known_vulnerabilities = match_vulnerabilities(parsed.package, version, vulnerability_records)
    judgement = judge_inspection(inspection, known_vulnerabilities=known_vulnerabilities, provenance=provenance)
    policy_result = evaluate_package_policy(judgement, non_interactive=True)
    decision = policy_result.decision
    risk_level = policy_result.risk_level
    policy_reasons = list(policy_result.reasons)
    if artifact_summary.sha256_status == "mismatch":
        decision = AgentDecision.BLOCK
        risk_level = RiskLevel.CRITICAL
        policy_reasons.append("Downloaded artifact hash did not match PyPI metadata.")
    warnings.extend(judgement.warnings)
    warnings.extend(policy_result.warnings)
    evidence.extend(judgement.evidence)
    evidence.append("Did not install, import, or execute inspected package code.")

    static_summary = _static_summary(judgement)
    if artifact_summary.status in {"inspected", "kept", "partial"}:
        static_summary.status = "downloaded_artifact_static_analysis"
        static_summary.sources = ["downloaded_artifact_files"]

    return PreInstallPackagePrecheckResult(
        requested=parsed.requested,
        package=parsed.package,
        normalized_package=parsed.normalized_package,
        requested_specifier=parsed.specifier,
        requested_version=parsed.exact_version,
        version=judgement.version or version,
        metadata_source=metadata_source,
        lookup_status=lookup_status,
        network_requested=pypi or osv or download_artifacts,
        artifacts_downloaded=artifact_summary.status in {"inspected", "kept", "partial"},
        decision=decision,
        exit_code=_exit_code_for_precheck(decision, lookup_status, artifact_summary.status),
        risk_level=risk_level,
        confidence=policy_result.confidence,
        policy_decision=decision,
        policy_reasons=policy_reasons,
        summary=judgement.summary,
        recommendation=policy_result.recommendation,
        warnings=sorted(set(warnings)),
        evidence=_dedupe_preserve_order(evidence),
        vulnerability_summary=_vulnerability_summary(known_vulnerabilities, vulnerability_sources, warnings),
        provenance_summary=_provenance_summary(judgement.provenance),
        typosquat_summary=_typosquat_summary(parsed.package),
        static_summary=static_summary,
        artifact_summary=artifact_summary,
        package_judgement=judgement,
    )


def build_requirements_precheck(
    path: Path,
    *,
    pypi: bool = False,
    osv: bool = False,
    osv_cache_dir: Path | None = None,
    vulnerability_file: Path | None = None,
    download_artifacts: bool = False,
    keep_artifacts: bool = False,
    artifact_dir: Path | None = None,
) -> PrecheckBatchResult:
    """Build precheck results for a requirements file without installing dependencies."""

    declarations = _requirements_from_file(path)
    return _build_batch_precheck(
        target_type="requirements",
        source=str(path),
        requirements=declarations.requirements,
        input_warnings=declarations.warnings,
        pypi=pypi,
        osv=osv,
        osv_cache_dir=osv_cache_dir,
        vulnerability_file=vulnerability_file,
        download_artifacts=download_artifacts,
        keep_artifacts=keep_artifacts,
        artifact_dir=artifact_dir,
    )


def build_pyproject_precheck(
    path: Path,
    *,
    pypi: bool = False,
    osv: bool = False,
    osv_cache_dir: Path | None = None,
    vulnerability_file: Path | None = None,
    download_artifacts: bool = False,
    keep_artifacts: bool = False,
    artifact_dir: Path | None = None,
) -> PrecheckBatchResult:
    """Build precheck results for PEP 621 pyproject dependencies."""

    declarations = _requirements_from_pyproject(path)
    return _build_batch_precheck(
        target_type="pyproject",
        source=str(path),
        requirements=declarations.requirements,
        input_warnings=declarations.warnings,
        pypi=pypi,
        osv=osv,
        osv_cache_dir=osv_cache_dir,
        vulnerability_file=vulnerability_file,
        download_artifacts=download_artifacts,
        keep_artifacts=keep_artifacts,
        artifact_dir=artifact_dir,
    )


def parse_precheck_target(target: str) -> ParsedPrecheckTarget:
    stripped = target.strip()
    if not stripped:
        raise PrecheckTargetError("precheck target must not be empty")
    try:
        requirement = Requirement(stripped)
    except InvalidRequirement as exc:
        raise PrecheckTargetError(f"precheck target must be a package requirement: {target}") from exc
    exact_version = _exact_version(requirement)
    specifier = str(requirement.specifier) or None
    if requirement.url:
        raise PrecheckTargetError("precheck does not evaluate direct URL, VCS, or file requirements")
    return ParsedPrecheckTarget(
        requested=stripped,
        package=requirement.name,
        normalized_package=canonicalize_name(requirement.name),
        specifier=specifier,
        exact_version=exact_version,
    )


def _build_batch_precheck(
    *,
    target_type: str,
    source: str,
    requirements: list[str],
    input_warnings: list[str] | None,
    pypi: bool,
    osv: bool,
    osv_cache_dir: Path | None,
    vulnerability_file: Path | None,
    download_artifacts: bool,
    keep_artifacts: bool,
    artifact_dir: Path | None,
) -> PrecheckBatchResult:
    results = [
        build_package_precheck(
            requirement,
            pypi=pypi,
            osv=osv,
            osv_cache_dir=osv_cache_dir,
            vulnerability_file=vulnerability_file,
            download_artifacts=download_artifacts,
            keep_artifacts=keep_artifacts,
            artifact_dir=artifact_dir,
        )
        for requirement in requirements
    ]
    warnings: list[str] = []
    warnings.extend(input_warnings or [])
    if not requirements:
        warnings.append(f"No supported package requirements found in {source}.")
    warnings.extend(warning for result in results for warning in result.warnings)
    return PrecheckBatchResult(
        target_type=target_type,
        source=source,
        package_count=len(results),
        decision=_strictest_decision([result.decision for result in results]),
        exit_code=_batch_exit_code(results),
        risk_level=_highest_risk([result.risk_level for result in results]),
        confidence=_lowest_confidence([result.confidence for result in results]),
        warnings=sorted(set(warnings)),
        results=results,
    )


def _requirements_from_file(path: Path) -> DependencyDeclarations:
    if not path.exists():
        raise PrecheckFileError(f"requirements file not found: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PrecheckFileError(f"could not read requirements file {path}: {exc}") from exc
    requirements: list[str] = []
    warnings: list[str] = []
    for line_number, line in _logical_requirement_lines(lines):
        cleaned = line.split("#", 1)[0].strip()
        if not cleaned:
            continue
        if cleaned.startswith(("-r", "--requirement")):
            warnings.append(f"Skipped requirements line {line_number}: recursive include is not evaluated by precheck.")
            continue
        if cleaned.startswith(("-e", "--editable")):
            warnings.append(f"Skipped requirements line {line_number}: editable requirement is not evaluated by precheck.")
            continue
        if cleaned.startswith(("http:", "https:", "git+", "svn+", "hg+", "bzr+", "file://")):
            warnings.append(f"Skipped requirements line {line_number}: URL, VCS, or file requirement is not evaluated by precheck.")
            continue
        if cleaned.startswith("-"):
            warnings.append(f"Skipped requirements line {line_number}: requirements option is not evaluated by precheck.")
            continue
        normalized = _normalize_requirement_line(cleaned)
        if normalized is None:
            warnings.append(f"Skipped requirements line {line_number}: malformed package requirement.")
            continue
        try:
            requirement = Requirement(normalized)
        except InvalidRequirement:
            warnings.append(f"Skipped requirements line {line_number}: malformed package requirement.")
            continue
        if requirement.url:
            warnings.append(
                f"Skipped requirements line {line_number}: URL, VCS, or file requirement is not evaluated by precheck."
            )
            continue
        requirements.append(normalized)
    return DependencyDeclarations(requirements=requirements, warnings=warnings)


def _requirements_from_pyproject(path: Path) -> DependencyDeclarations:
    if not path.exists():
        raise PrecheckFileError(f"pyproject file not found: {path}")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PrecheckFileError(f"could not read pyproject dependencies from {path}: {exc}") from exc
    project = data.get("project")
    project = project if isinstance(project, dict) else {}
    requirements: list[str] = []
    warnings: list[str] = []
    dependencies = project.get("dependencies", [])
    if dependencies is not None and not isinstance(dependencies, list):
        warnings.append("Skipped project.dependencies: value is not a list.")
        dependencies = []
    for index, dependency in enumerate(dependencies, start=1):
        if not isinstance(dependency, str):
            warnings.append(f"Skipped project.dependencies entry {index}: dependency is not a string.")
        elif _is_valid_requirement(dependency):
            requirements.append(dependency)
        else:
            warnings.append(f"Skipped project.dependencies entry {index}: malformed package requirement.")
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for group, dependencies in optional.items():
            if not isinstance(dependencies, list):
                warnings.append(f"Skipped project.optional-dependencies.{group}: value is not a list.")
                continue
            for index, dependency in enumerate(dependencies, start=1):
                if not isinstance(dependency, str):
                    warnings.append(
                        f"Skipped project.optional-dependencies.{group} entry {index}: dependency is not a string."
                    )
                elif _is_valid_requirement(dependency):
                    requirements.append(dependency)
                else:
                    warnings.append(
                        f"Skipped project.optional-dependencies.{group} entry {index}: malformed package requirement."
                    )
    return DependencyDeclarations(requirements=requirements, warnings=warnings)


def _is_valid_requirement(value: str) -> bool:
    try:
        requirement = Requirement(value)
    except InvalidRequirement:
        return False
    return requirement.url is None


def _strictest_decision(decisions: list[AgentDecision]) -> AgentDecision:
    if not decisions:
        return AgentDecision.REVIEW_MANUALLY
    order = {
        AgentDecision.ALLOW: 0,
        AgentDecision.ALLOW_WITH_CAUTION: 1,
        AgentDecision.REVIEW_MANUALLY: 2,
        AgentDecision.SANDBOX_ONLY: 3,
        AgentDecision.BLOCK: 4,
    }
    return max(decisions, key=lambda decision: order[decision])


def _exit_code_for_precheck(decision: AgentDecision, lookup_status: str, artifact_status: str) -> int:
    if lookup_status == "online_metadata_unavailable" or artifact_status in {"failed", "unavailable", "partial"}:
        return 4
    if decision in {AgentDecision.BLOCK, AgentDecision.SANDBOX_ONLY}:
        return 2
    if decision in {AgentDecision.ALLOW_WITH_CAUTION, AgentDecision.REVIEW_MANUALLY}:
        return 1
    return 0


def _batch_exit_code(results: list[PreInstallPackagePrecheckResult]) -> int:
    if not results:
        return 4
    order = {0: 0, 1: 1, 2: 2, 4: 3}
    return max((result.exit_code for result in results), key=lambda code: order.get(code, code))


def _highest_risk(risks: list[RiskLevel]) -> RiskLevel:
    if not risks:
        return RiskLevel.UNKNOWN
    order = {"low": 0, "medium": 1, "unknown": 1, "high": 2, "critical": 3}
    return max(risks, key=lambda risk: order[risk.value])


def _lowest_confidence(confidences: list[Confidence]) -> Confidence:
    if not confidences:
        return Confidence.LOW
    order = {"low": 0, "medium": 1, "high": 2}
    return min(confidences, key=lambda confidence: order[confidence.value])


def _release_exists(payload: dict[str, Any], version: str) -> bool:
    releases = payload.get("releases")
    return isinstance(releases, dict) and isinstance(releases.get(version), list)


def _select_release_version(payload: dict[str, Any], parsed: ParsedPrecheckTarget) -> str | None:
    if parsed.exact_version:
        return parsed.exact_version if _release_exists(payload, parsed.exact_version) else None

    releases = payload.get("releases")
    if not isinstance(releases, dict):
        return None
    specifier = SpecifierSet(parsed.specifier or "")
    candidates: list[tuple[Version, str]] = []
    for version_text, files in releases.items():
        if not isinstance(version_text, str) or not isinstance(files, list) or not files:
            continue
        try:
            version = Version(version_text)
        except InvalidVersion:
            continue
        candidates.append((version, version_text))
    if specifier:
        matching = [item for item in candidates if specifier.contains(item[0])]
        if not matching:
            matching = [item for item in candidates if specifier.contains(item[0], prereleases=True)]
        return max(matching, key=lambda item: item[0])[1] if matching else None
    stable_candidates = [item for item in candidates if not item[0].is_prerelease]
    if stable_candidates:
        return max(stable_candidates, key=lambda item: item[0])[1]
    if candidates:
        return max(candidates, key=lambda item: item[0])[1]

    info = payload.get("info")
    info = info if isinstance(info, dict) else {}
    info_version = _string_or_none(info.get("version"))
    if info_version and not parsed.specifier:
        return info_version
    return None


def _release_unavailable_warning(parsed: ParsedPrecheckTarget) -> str:
    if parsed.exact_version:
        return f"PyPI metadata did not list requested release version {parsed.exact_version}."
    if parsed.specifier:
        return f"PyPI metadata did not list a release satisfying {parsed.specifier}."
    return "PyPI metadata did not list a usable release for precheck."


def _inspection_from_pypi_payload(
    parsed: ParsedPrecheckTarget,
    payload: dict[str, Any],
    release_version: str | None,
) -> PackageInspection:
    info = payload.get("info")
    info = info if isinstance(info, dict) else {}
    project_urls = _project_urls(info)
    version = release_version or _string_or_none(info.get("version"))
    info_version = _string_or_none(info.get("version"))
    version_specific_info = release_version is None or info_version in {None, release_version}
    warnings = [
        "Precheck used PyPI metadata only; artifacts were not downloaded or statically inspected.",
        "Metadata-only precheck cannot prove package contents are safe.",
    ]
    evidence = [
        "Read package identity and project metadata from PyPI JSON.",
        "Did not download, install, import, or execute package artifacts.",
    ]
    if not version_specific_info:
        warnings.append(
            "Selected PyPI release differs from project-level info.version; version-specific summary, author, license, and dependency metadata were not inferred."
        )
        evidence.append("Used selected release version from PyPI releases and omitted latest-project-only metadata fields.")
    metadata = PackageMetadata(
        identity=PackageIdentity(
            name=_string_or_none(info.get("name")) or parsed.package,
            normalized_name=parsed.normalized_package,
            version=version,
        ),
        summary=_string_or_none(info.get("summary")) if version_specific_info else None,
        author=_string_or_none(info.get("author")) if version_specific_info else None,
        maintainer=_string_or_none(info.get("maintainer")) if version_specific_info else None,
        license=_string_or_none(info.get("license")) if version_specific_info else None,
        requires=[value for value in info.get("requires_dist") or [] if isinstance(value, str)] if version_specific_info else [],
        project_urls=project_urls,
        metadata_available=True,
    )
    return PackageInspection(
        metadata=metadata,
        source_availability=SourceAvailability.SOURCE_AVAILABILITY_UNKNOWN,
        readability=ReadabilityStatus.NOT_ENOUGH_SOURCE_AVAILABLE,
        size=measure_distribution_size(None),
        package_paths=[],
        detected_capabilities=[],
        warnings=warnings,
        evidence=evidence,
        file_analysis=FileStaticAnalysis(),
    )


@dataclass(frozen=True)
class ArtifactReview:
    inspection: PackageInspection
    summary: PrecheckArtifactSummary


def _inspect_downloaded_artifact(
    parsed: ParsedPrecheckTarget,
    payload: dict[str, Any],
    *,
    metadata: PackageMetadata,
    keep_artifacts: bool,
    artifact_dir: Path | None,
) -> ArtifactReview:
    artifact = _select_artifact(payload, metadata.identity.version)
    if artifact is None:
        return ArtifactReview(
            inspection=_inspection_from_metadata_without_artifact(metadata),
            summary=PrecheckArtifactSummary(
                status="unavailable",
                warnings=["PyPI metadata did not list a wheel or source artifact for the requested release."],
            ),
        )
    raw_filename = _string_or_none(artifact.get("filename")) or ""
    try:
        filename = _safe_artifact_filename(raw_filename)
    except ValueError as exc:
        return ArtifactReview(
            inspection=_inspection_from_metadata_without_artifact(metadata),
            summary=PrecheckArtifactSummary(
                status="failed",
                filename=raw_filename or None,
                package_type=artifact.get("packagetype"),
                url=_safe_artifact_url(artifact.get("url")),
                warnings=[f"Artifact download/static inspection failed: {exc}"],
            ),
        )

    review_root_manager = None
    try:
        if keep_artifacts:
            review_root = (artifact_dir or Path.cwd() / ".pkgwhy-artifacts").expanduser()
            review_root.mkdir(parents=True, exist_ok=True)
            review_root = review_root / f"{parsed.normalized_package}-{filename}"
            if review_root.exists():
                shutil.rmtree(review_root)
            review_root.mkdir(parents=True)
        else:
            review_root_manager = tempfile.TemporaryDirectory(prefix="pkgwhy-artifact-")
            review_root = Path(review_root_manager.name)
        artifact_path = review_root / filename
        downloaded = _download_url(artifact["url"])
        artifact_path.write_bytes(downloaded)
        sha256_status = _sha256_status(downloaded, artifact.get("sha256"))
        extract_root = review_root / "extracted"
        extract_root.mkdir()
        extracted_paths = _extract_artifact(artifact_path, extract_root)
        inspection = _inspection_from_artifact_paths(metadata, extracted_paths)
        status = "kept" if keep_artifacts else "inspected"
        warnings = []
        if sha256_status == "mismatch":
            warnings.append("Downloaded artifact SHA-256 did not match PyPI metadata.")
        excluded_filenames = artifact.get("excluded_filenames")
        excluded_count = len(excluded_filenames) if isinstance(excluded_filenames, list) else 0
        if excluded_count:
            status = "partial"
            preview = ", ".join(str(name) for name in excluded_filenames[:5])
            if excluded_count > 5:
                preview = f"{preview}, ..."
            warnings.append(
                f"Artifact precheck inspected one selected release artifact; "
                f"{excluded_count} additional artifact(s) were not inspected: {preview}."
            )
        evidence = [
            f"Downloaded PyPI artifact {filename} for static inspection.",
            f"SHA-256 status: {sha256_status}.",
            f"Extracted {len(extracted_paths)} files without installing or executing package code.",
        ]
        if excluded_count:
            evidence.append(
                f"Selected one artifact from {artifact.get('candidate_count', excluded_count + 1)} candidate release artifacts."
            )
        if not keep_artifacts:
            evidence.append("Temporary artifact review directory was deleted after inspection.")
        return ArtifactReview(
            inspection=inspection,
            summary=PrecheckArtifactSummary(
                status=status,
                filename=filename,
                package_type=artifact.get("packagetype"),
                url=_safe_artifact_url(artifact.get("url")),
                sha256_status=sha256_status,
                size_bytes=len(downloaded),
                extracted_file_count=len(extracted_paths),
                kept_path=str(review_root) if keep_artifacts else None,
                warnings=warnings,
                evidence=evidence,
            ),
        )
    except (OSError, zipfile.BadZipFile, tarfile.TarError, ValueError, ArtifactDownloadError) as exc:
        return ArtifactReview(
            inspection=_inspection_from_metadata_without_artifact(metadata),
            summary=PrecheckArtifactSummary(
                status="failed",
                filename=filename,
                package_type=artifact.get("packagetype"),
                url=_safe_artifact_url(artifact.get("url")),
                warnings=[f"Artifact download/static inspection failed: {exc}"],
            ),
        )
    finally:
        if review_root_manager is not None:
            review_root_manager.cleanup()


class ArtifactDownloadError(RuntimeError):
    """Raised when an explicit artifact download request cannot retrieve bytes."""


def _safe_artifact_filename(filename: str) -> str:
    if Path(filename).name != filename or filename in {"", ".", ".."}:
        raise ValueError(f"unsafe artifact filename: {filename}")
    return filename


def _download_url(url: str, *, timeout_seconds: float = 15.0, max_bytes: int = MAX_ARTIFACT_DOWNLOAD_BYTES) -> bytes:
    req = request.Request(url, headers={"Accept": "application/octet-stream"}, method="GET")
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    declared_size = None
                if declared_size is not None and declared_size > max_bytes:
                    raise ArtifactDownloadError(
                        f"artifact download exceeds {max_bytes} byte limit before reading response"
                    )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ArtifactDownloadError(f"artifact download exceeds {max_bytes} byte limit")
                chunks.append(chunk)
            return b"".join(chunks)
    except (OSError, error.HTTPError) as exc:
        raise ArtifactDownloadError(f"artifact download failed for {url}: {exc}") from exc


def _select_artifact(payload: dict[str, Any], version: str | None) -> dict[str, Any] | None:
    info = payload.get("info")
    info = info if isinstance(info, dict) else {}
    release_version = version or _string_or_none(info.get("version"))
    releases = payload.get("releases")
    if not isinstance(releases, dict) or release_version is None:
        return None
    files = releases.get(release_version)
    if not isinstance(files, list):
        return None
    candidates: list[dict[str, Any]] = []
    for file_info in files:
        if not isinstance(file_info, dict):
            continue
        filename = _string_or_none(file_info.get("filename"))
        url = _string_or_none(file_info.get("url"))
        if filename is None or url is None:
            continue
        packagetype = _string_or_none(file_info.get("packagetype")) or "unknown"
        if packagetype not in {"bdist_wheel", "sdist"} and not filename.endswith((".whl", ".tar.gz", ".zip")):
            continue
        digests = file_info.get("digests")
        digests = digests if isinstance(digests, dict) else {}
        candidates.append(
            {
                "filename": filename,
                "url": url,
                "packagetype": packagetype,
                "sha256": _string_or_none(digests.get("sha256")) or "",
            }
        )
    if not candidates:
        return None
    sorted_candidates = sorted(candidates, key=lambda item: (0 if item["packagetype"] == "bdist_wheel" else 1, item["filename"]))
    selected = dict(sorted_candidates[0])
    selected["candidate_count"] = len(sorted_candidates)
    selected["excluded_filenames"] = [item["filename"] for item in sorted_candidates[1:]]
    return selected


def _sha256_status(data: bytes, expected: str | None) -> str:
    if not expected:
        return "not_available"
    actual = hashlib.sha256(data).hexdigest()
    return "verified" if actual == expected else "mismatch"


def _safe_artifact_url(value: Any) -> str | None:
    url = _string_or_none(value)
    if url is None:
        return None
    parts = parse.urlsplit(url)
    host = parts.hostname or ""
    if not host:
        return None
    netloc = host
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    basename = Path(parts.path).name
    safe_path = f"/{basename}" if basename else ""
    return parse.urlunsplit((parts.scheme, netloc, safe_path, "", ""))


def _extract_artifact(artifact_path: Path, extract_root: Path) -> list[Path]:
    if artifact_path.suffix == ".whl" or artifact_path.suffix == ".zip":
        return _extract_zip(artifact_path, extract_root)
    if artifact_path.name.endswith((".tar.gz", ".tgz")):
        return _extract_tar(artifact_path, extract_root)
    raise ValueError(f"unsupported artifact type for static inspection: {artifact_path.name}")


def _extract_zip(artifact_path: Path, extract_root: Path) -> list[Path]:
    with zipfile.ZipFile(artifact_path) as archive:
        members = []
        total_size = 0
        for member in archive.infolist():
            if member.is_dir():
                continue
            total_size = _check_extract_limits(len(members) + 1, total_size, member.file_size, member.filename)
            target = (extract_root / member.filename).resolve()
            if not target.is_relative_to(extract_root.resolve()):
                raise ValueError(f"unsafe archive path: {member.filename}")
            archive.extract(member, extract_root)
            members.append(target)
    return members


def _extract_tar(artifact_path: Path, extract_root: Path) -> list[Path]:
    with tarfile.open(artifact_path) as archive:
        members = []
        total_size = 0
        extract_root_resolved = extract_root.resolve()
        for member in archive.getmembers():
            if not member.isfile():
                continue
            total_size = _check_extract_limits(len(members) + 1, total_size, member.size, member.name)
            target = (extract_root / member.name).resolve()
            if not target.is_relative_to(extract_root_resolved):
                raise ValueError(f"unsafe archive path: {member.name}")
            source = archive.extractfile(member)
            if source is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("wb") as destination:
                shutil.copyfileobj(source, destination)
            members.append(target)
    return members


def _check_extract_limits(member_count: int, current_size: int, next_size: int, name: str) -> int:
    if member_count > MAX_ARTIFACT_FILE_COUNT:
        raise ValueError(f"artifact extraction exceeds {MAX_ARTIFACT_FILE_COUNT} file limit")
    if next_size < 0:
        raise ValueError(f"artifact member has invalid size: {name}")
    total_size = current_size + next_size
    if total_size > MAX_ARTIFACT_EXTRACTED_BYTES:
        raise ValueError(f"artifact extraction exceeds {MAX_ARTIFACT_EXTRACTED_BYTES} byte uncompressed limit")
    return total_size


def _inspection_from_metadata_without_artifact(metadata: PackageMetadata) -> PackageInspection:
    return PackageInspection(
        metadata=metadata,
        source_availability=SourceAvailability.SOURCE_AVAILABILITY_UNKNOWN,
        readability=ReadabilityStatus.NOT_ENOUGH_SOURCE_AVAILABLE,
        size=measure_distribution_size(None),
        package_paths=[],
        detected_capabilities=[],
        warnings=["Artifact static inspection did not produce file evidence."],
        evidence=["Did not install, import, or execute package artifacts."],
        file_analysis=FileStaticAnalysis(),
    )


def _inspection_from_artifact_paths(metadata: PackageMetadata, paths: list[Path]) -> PackageInspection:
    file_analysis = analyze_file_signals(paths, metadata.entry_points)
    python_analysis = analyze_python_files(paths)
    capabilities = sorted(set(file_analysis.detected_capabilities) | set(python_analysis.detected_capabilities))
    evidence = [
        "Statically inspected downloaded package artifact files.",
        f"Statically parsed {python_analysis.files_scanned} Python files with AST.",
        "Did not install, import, or execute downloaded artifact code.",
    ]
    evidence.extend(file_analysis.evidence)
    evidence.extend(python_analysis.evidence)
    warnings = list(file_analysis.warnings)
    warnings.extend(python_analysis.warnings)
    rule_evidence = list(file_analysis.rule_evidence)
    rule_evidence.extend(python_analysis.rule_evidence)
    return PackageInspection(
        metadata=metadata,
        source_availability=SourceAvailability.ARTIFACT_SOURCE_PRESENT,
        readability=infer_readability(paths, file_analysis),
        size=_measure_paths(paths),
        package_paths=[Path(path) for path in paths[:20]],
        detected_capabilities=capabilities,
        warnings=warnings,
        evidence=evidence,
        rule_evidence=rule_evidence,
        file_analysis=file_analysis,
    )


def _measure_paths(paths: list[Path]) -> PackageSize:
    python_bytes = 0
    native_bytes = 0
    javascript_bytes = 0
    other_bytes = 0
    largest = []
    for path in paths:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        suffix = path.suffix.lower()
        if suffix == ".py":
            python_bytes += size
        elif suffix in {".so", ".pyd", ".dll", ".dylib", ".exe"}:
            native_bytes += size
        elif suffix == ".js":
            javascript_bytes += size
        else:
            other_bytes += size
        largest.append((str(path), size))
    largest_files = [
        {"path": path, "size_bytes": size}
        for path, size in sorted(largest, key=lambda item: item[1], reverse=True)[:5]
    ]
    return PackageSize(
        total_bytes=python_bytes + native_bytes + javascript_bytes + other_bytes,
        python_bytes=python_bytes,
        native_binary_bytes=native_bytes,
        javascript_bytes=javascript_bytes,
        other_bytes=other_bytes,
        file_count=len(paths),
        largest_files=largest_files,
    )


def _unavailable_inspection(parsed: ParsedPrecheckTarget) -> PackageInspection:
    metadata = PackageMetadata(
        identity=PackageIdentity(
            name=parsed.package,
            normalized_name=parsed.normalized_package,
            version=parsed.exact_version,
        ),
        metadata_available=False,
    )
    return PackageInspection(
        metadata=metadata,
        source_availability=SourceAvailability.NOT_INSTALLED,
        readability=ReadabilityStatus.NOT_ENOUGH_SOURCE_AVAILABLE,
        size=measure_distribution_size(None),
        package_paths=[],
        detected_capabilities=[],
        warnings=["Package metadata is unavailable in the current precheck mode."],
        evidence=["Checked local environment metadata without importing package code."],
        file_analysis=FileStaticAnalysis(),
    )


def _project_urls(info: dict[str, Any]) -> ProjectUrls:
    raw = info.get("project_urls")
    raw_urls = {
        str(key): value.strip()
        for key, value in raw.items()
        if isinstance(key, str) and isinstance(value, str) and value.strip()
    } if isinstance(raw, dict) else {}
    homepage = _string_or_none(info.get("home_page")) or _find_url(raw_urls, ("homepage", "home-page"))
    repository = _find_url(raw_urls, ("source", "repository", "github", "code"))
    documentation = _find_url(raw_urls, ("doc", "documentation"))
    return ProjectUrls(homepage=homepage, repository=repository, documentation=documentation, raw=raw_urls)


def _vulnerability_summary(
    matches: list[VulnerabilityMatch],
    sources: list[str],
    warnings: list[str],
) -> PrecheckSignalSummary:
    if matches:
        status = "matches_found"
    elif sources:
        status = "no_matches_from_requested_sources"
    else:
        status = "not_requested"
    return PrecheckSignalSummary(
        status=status,
        sources=sorted(set(sources)),
        match_count=len(matches),
        warning_count=sum(1 for warning in warnings if "vulnerab" in warning.lower() or "osv" in warning.lower()),
        warnings=[warning for warning in warnings if "vulnerab" in warning.lower() or "osv" in warning.lower()],
        evidence=[item for match in matches for item in match.evidence],
    )


def _provenance_summary(provenance: PackageProvenance | None) -> PrecheckSignalSummary:
    if provenance is None:
        return PrecheckSignalSummary(status="unavailable")
    return PrecheckSignalSummary(
        status=provenance.metadata_source,
        sources=[provenance.metadata_source],
        warning_count=len(provenance.warnings),
        warnings=provenance.warnings,
        evidence=provenance.evidence,
    )


def _typosquat_summary(package: str) -> PrecheckSignalSummary:
    candidate = detect_typosquat(package)
    if candidate is None:
        return PrecheckSignalSummary(status="no_similarity_signal")
    return PrecheckSignalSummary(
        status="possible_typosquatting_signal",
        sources=["local_popular_package_similarity"],
        match_count=1,
        warning_count=1,
        warnings=[candidate.recommendation],
        evidence=candidate.evidence,
    )


def _static_summary(judgement) -> PrecheckSignalSummary:
    static_rules = [rule for rule in judgement.risk_rules if rule.category == RuleCategory.STATIC_ANALYSIS]
    if judgement.source_availability == SourceAvailability.NOT_INSTALLED:
        status = "not_available"
    elif static_rules or judgement.detected_capabilities:
        status = "static_signals_found"
    elif judgement.installed_size_bytes:
        status = "installed_distribution_static_analysis"
    else:
        status = "not_requested"
    return PrecheckSignalSummary(
        status=status,
        sources=["installed_distribution_files"] if judgement.installed_size_bytes or static_rules else [],
        match_count=len(static_rules),
        warning_count=len([warning for warning in judgement.warnings if "static" in warning.lower()]),
        warnings=[warning for warning in judgement.warnings if "static" in warning.lower()],
        evidence=[item for rule in static_rules for item in rule.evidence],
    )


def _exact_version(requirement: Requirement) -> str | None:
    exact_versions = [specifier.version for specifier in requirement.specifier if _is_exact_pin(specifier)]
    return exact_versions[0] if len(exact_versions) == 1 else None


def _is_exact_pin(specifier: Specifier) -> bool:
    return specifier.operator in {"==", "==="} and "*" not in specifier.version


def _logical_requirement_lines(lines: list[str]) -> list[tuple[int, str]]:
    logical_lines: list[tuple[int, str]] = []
    buffer = ""
    start_line = 1
    for line_number, line in enumerate(lines, start=1):
        stripped = line.rstrip()
        if not buffer:
            start_line = line_number
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        logical_lines.append((start_line, buffer + stripped))
        buffer = ""
    if buffer:
        logical_lines.append((start_line, buffer))
    return logical_lines


def _normalize_requirement_line(value: str) -> str | None:
    try:
        parts = shlex.split(value)
    except ValueError:
        return None
    if not parts:
        return None
    requirement_parts: list[str] = []
    skip_next = False
    for part in parts:
        if skip_next:
            skip_next = False
            continue
        if part == "--hash":
            skip_next = True
            continue
        if part.startswith("--hash="):
            continue
        if part.startswith("-"):
            return None
        requirement_parts.append(part)
    if not requirement_parts:
        return None
    return " ".join(requirement_parts)


def _find_url(values: dict[str, str], tokens: tuple[str, ...]) -> str | None:
    for key, value in values.items():
        lower = key.lower()
        if any(token in lower for token in tokens):
            return value
    return None


def _string_or_none(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped if stripped else None


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped

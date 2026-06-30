from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import Specifier
from packaging.utils import canonicalize_name

from pkgwhy.agent.judge import inspect_installed_package, judge_installed_package
from pkgwhy.core.models import (
    AgentDecision,
    Confidence,
    FileStaticAnalysis,
    PackageIdentity,
    PackageInspection,
    PackageMetadata,
    PackageProvenance,
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
from pkgwhy.inspection.size import measure_distribution_size
from pkgwhy.metadata.installed import get_installed_package
from pkgwhy.metadata.pypi import PyPIMetadataError, fetch_pypi_project, provenance_from_pypi_payload
from pkgwhy.policy.agent_policy import evaluate_package_policy
from pkgwhy.risk.scoring import judge_inspection
from pkgwhy.typosquat.detector import detect_typosquat
from pkgwhy.vulnerabilities.matching import match_vulnerabilities
from pkgwhy.vulnerabilities.osv import load_osv_records, query_osv_cached


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


def build_package_precheck(
    target: str,
    *,
    pypi: bool = False,
    osv: bool = False,
    osv_cache_dir: Path | None = None,
    vulnerability_file: Path | None = None,
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

    if vulnerability_file is not None:
        try:
            vulnerability_records.extend(load_osv_records(vulnerability_file, package_name=parsed.package))
            vulnerability_sources.append(str(vulnerability_file))
        except ValueError as exc:
            warnings.append(str(exc))

    installed_metadata = get_installed_package(parsed.package)
    installed_inspection = inspect_installed_package(parsed.package)
    pypi_payload: dict[str, Any] | None = None

    if pypi:
        try:
            pypi_payload = fetch_pypi_project(parsed.package)
            metadata_source = "pypi_json"
            lookup_status = "metadata_found"
            evidence.append("Read PyPI project JSON because --pypi was explicitly requested.")
        except PyPIMetadataError as exc:
            warnings.append(
                f"PyPI metadata lookup unavailable for {parsed.package}: {exc}. "
                "No package safety result was inferred from the failed lookup."
            )
            lookup_status = "online_metadata_unavailable"

    if pypi_payload is not None:
        inspection = _inspection_from_pypi_payload(parsed, pypi_payload)
        provenance = provenance_from_pypi_payload(
            parsed.package,
            pypi_payload,
            audited_version=parsed.exact_version or inspection.metadata.identity.version,
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

    known_vulnerabilities = match_vulnerabilities(parsed.package, version, vulnerability_records)
    judgement = judge_inspection(inspection, known_vulnerabilities=known_vulnerabilities, provenance=provenance)
    policy_result = evaluate_package_policy(judgement, non_interactive=True)
    warnings.extend(judgement.warnings)
    warnings.extend(policy_result.warnings)
    evidence.extend(judgement.evidence)
    evidence.append("Did not install, import, or execute inspected package code.")

    return PreInstallPackagePrecheckResult(
        requested=parsed.requested,
        package=parsed.package,
        normalized_package=parsed.normalized_package,
        requested_specifier=parsed.specifier,
        requested_version=parsed.exact_version,
        version=judgement.version or version,
        metadata_source=metadata_source,
        lookup_status=lookup_status,
        network_requested=pypi or osv,
        artifacts_downloaded=False,
        decision=policy_result.decision,
        risk_level=policy_result.risk_level,
        confidence=policy_result.confidence,
        policy_decision=policy_result.decision,
        policy_reasons=policy_result.reasons,
        summary=judgement.summary,
        recommendation=policy_result.recommendation,
        warnings=sorted(set(warnings)),
        evidence=_dedupe_preserve_order(evidence),
        vulnerability_summary=_vulnerability_summary(known_vulnerabilities, vulnerability_sources, warnings),
        provenance_summary=_provenance_summary(judgement.provenance),
        typosquat_summary=_typosquat_summary(parsed.package),
        static_summary=_static_summary(judgement),
        package_judgement=judgement,
    )


def build_requirements_precheck(
    path: Path,
    *,
    pypi: bool = False,
    osv: bool = False,
    osv_cache_dir: Path | None = None,
    vulnerability_file: Path | None = None,
) -> PrecheckBatchResult:
    """Build precheck results for a requirements file without installing dependencies."""

    requirements = _requirements_from_file(path)
    return _build_batch_precheck(
        target_type="requirements",
        source=str(path),
        requirements=requirements,
        pypi=pypi,
        osv=osv,
        osv_cache_dir=osv_cache_dir,
        vulnerability_file=vulnerability_file,
    )


def build_pyproject_precheck(
    path: Path,
    *,
    pypi: bool = False,
    osv: bool = False,
    osv_cache_dir: Path | None = None,
    vulnerability_file: Path | None = None,
) -> PrecheckBatchResult:
    """Build precheck results for PEP 621 pyproject dependencies."""

    requirements = _requirements_from_pyproject(path)
    return _build_batch_precheck(
        target_type="pyproject",
        source=str(path),
        requirements=requirements,
        pypi=pypi,
        osv=osv,
        osv_cache_dir=osv_cache_dir,
        vulnerability_file=vulnerability_file,
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
    pypi: bool,
    osv: bool,
    osv_cache_dir: Path | None,
    vulnerability_file: Path | None,
) -> PrecheckBatchResult:
    results = [
        build_package_precheck(
            requirement,
            pypi=pypi,
            osv=osv,
            osv_cache_dir=osv_cache_dir,
            vulnerability_file=vulnerability_file,
        )
        for requirement in requirements
    ]
    warnings: list[str] = []
    if not requirements:
        warnings.append(f"No supported package requirements found in {source}.")
    warnings.extend(warning for result in results for warning in result.warnings)
    return PrecheckBatchResult(
        target_type=target_type,
        source=source,
        package_count=len(results),
        decision=_strictest_decision([result.decision for result in results]),
        risk_level=_highest_risk([result.risk_level for result in results]),
        confidence=_lowest_confidence([result.confidence for result in results]),
        warnings=sorted(set(warnings)),
        results=results,
    )


def _requirements_from_file(path: Path) -> list[str]:
    if not path.exists():
        raise PrecheckFileError(f"requirements file not found: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PrecheckFileError(f"could not read requirements file {path}: {exc}") from exc
    requirements: list[str] = []
    for line in lines:
        cleaned = line.split("#", 1)[0].strip()
        if not cleaned or cleaned.startswith(("-", "http:", "https:", "git+", "svn+", "hg+", "bzr+", "file://")):
            continue
        try:
            Requirement(cleaned)
        except InvalidRequirement:
            continue
        requirements.append(cleaned)
    return requirements


def _requirements_from_pyproject(path: Path) -> list[str]:
    if not path.exists():
        raise PrecheckFileError(f"pyproject file not found: {path}")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PrecheckFileError(f"could not read pyproject dependencies from {path}: {exc}") from exc
    project = data.get("project")
    project = project if isinstance(project, dict) else {}
    requirements: list[str] = []
    for dependency in project.get("dependencies", []):
        if isinstance(dependency, str) and _is_valid_requirement(dependency):
            requirements.append(dependency)
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for dependencies in optional.values():
            if not isinstance(dependencies, list):
                continue
            for dependency in dependencies:
                if isinstance(dependency, str) and _is_valid_requirement(dependency):
                    requirements.append(dependency)
    return requirements


def _is_valid_requirement(value: str) -> bool:
    try:
        Requirement(value)
    except InvalidRequirement:
        return False
    return True


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


def _inspection_from_pypi_payload(parsed: ParsedPrecheckTarget, payload: dict[str, Any]) -> PackageInspection:
    info = payload.get("info")
    info = info if isinstance(info, dict) else {}
    project_urls = _project_urls(info)
    version = parsed.exact_version or _string_or_none(info.get("version"))
    metadata = PackageMetadata(
        identity=PackageIdentity(
            name=_string_or_none(info.get("name")) or parsed.package,
            normalized_name=parsed.normalized_package,
            version=version,
        ),
        summary=_string_or_none(info.get("summary")),
        author=_string_or_none(info.get("author")),
        maintainer=_string_or_none(info.get("maintainer")),
        license=_string_or_none(info.get("license")),
        requires=[value for value in info.get("requires_dist") or [] if isinstance(value, str)],
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
        warnings=[
            "Precheck used PyPI metadata only; artifacts were not downloaded or statically inspected.",
            "Metadata-only precheck cannot prove package contents are safe.",
        ],
        evidence=[
            "Read package identity and project metadata from PyPI JSON.",
            "Did not download, install, import, or execute package artifacts.",
        ],
        file_analysis=FileStaticAnalysis(),
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

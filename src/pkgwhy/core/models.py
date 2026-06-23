from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from pkgwhy.core.constants import CAPABILITY_EXPOSURE_NOTE, PACKAGE_JUDGEMENT_SCHEMA_VERSION


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class AgentDecision(StrEnum):
    ALLOW = "allow"
    ALLOW_WITH_CAUTION = "allow_with_caution"
    REVIEW_MANUALLY = "review_manually"
    SANDBOX_ONLY = "sandbox_only"
    BLOCK = "block"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DependencyStatus(StrEnum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    IMPORTED_BY_PROJECT = "imported_by_project"
    NOT_INSTALLED = "not_installed"
    UNKNOWN = "unknown"


class SourceAvailability(StrEnum):
    INSTALLED_SOURCE_PRESENT = "installed_source_present"
    INSTALLED_METADATA_ONLY = "installed_metadata_only"
    SOURCE_AVAILABILITY_UNKNOWN = "source_availability_unknown"
    NOT_INSTALLED = "not_installed"


class ReadabilityStatus(StrEnum):
    READABLE = "readable"
    MOSTLY_READABLE = "mostly_readable"
    PARTIALLY_READABLE = "partially_readable"
    MINIFIED = "minified"
    POSSIBLY_OBFUSCATED = "possibly_obfuscated"
    LIKELY_OBFUSCATED = "likely_obfuscated"
    NOT_ENOUGH_SOURCE_AVAILABLE = "not_enough_source_available"


class PackageIdentity(BaseModel):
    """Installed package identity fields using both display and normalized names."""

    name: str
    normalized_name: str
    version: str | None = None


class ProjectUrls(BaseModel):
    """Project URLs extracted from installed distribution metadata."""

    homepage: str | None = None
    repository: str | None = None
    documentation: str | None = None
    raw: dict[str, str] = Field(default_factory=dict)


class PackageMetadata(BaseModel):
    """Installed distribution metadata gathered without importing package code."""

    identity: PackageIdentity
    summary: str | None = None
    author: str | None = None
    maintainer: str | None = None
    license: str | None = None
    requires: list[str] = Field(default_factory=list)
    project_urls: ProjectUrls = Field(default_factory=ProjectUrls)
    entry_points: list[str] = Field(default_factory=list)
    metadata_available: bool = True


class LargestFile(BaseModel):
    """A large installed file reported as inspection evidence."""

    path: str
    size_bytes: int


class PackageSize(BaseModel):
    """Installed package size totals grouped by coarse file category."""

    total_bytes: int = 0
    python_bytes: int = 0
    native_binary_bytes: int = 0
    javascript_bytes: int = 0
    other_bytes: int = 0
    file_count: int = 0
    largest_files: list[LargestFile] = Field(default_factory=list)


class PythonStaticAnalysis(BaseModel):
    """AST-derived Python capability signals and parse warnings."""

    detected_capabilities: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    files_scanned: int = 0


class FileStaticAnalysis(BaseModel):
    """Static file-type and text-pattern signals gathered without execution."""

    detected_capabilities: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    javascript_files_scanned: int = 0
    shell_scripts_detected: int = 0
    native_binaries_detected: int = 0
    wasm_files_detected: int = 0
    setup_files_detected: int = 0


class PackageInspection(BaseModel):
    """Static inspection result combining metadata, files, warnings, and evidence."""

    metadata: PackageMetadata
    source_availability: SourceAvailability
    readability: ReadabilityStatus
    size: PackageSize
    package_paths: list[Path] = Field(default_factory=list)
    detected_capabilities: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    file_analysis: FileStaticAnalysis = Field(default_factory=FileStaticAnalysis)


class PackageExplanation(BaseModel):
    """Human-readable package explanation assembled from local and installed sources."""

    package: str
    version: str | None = None
    summary: str
    common_use_cases: list[str] = Field(default_factory=list)
    common_imports: list[str] = Field(default_factory=list)
    minimal_usage_example: str | None = None
    common_alternatives: list[str] = Field(default_factory=list)
    why_it_might_be_installed: list[str] = Field(default_factory=list)
    dependency_status: DependencyStatus = DependencyStatus.UNKNOWN
    confidence: Confidence = Confidence.LOW
    sources_used: list[str] = Field(default_factory=list)


class PackageJudgement(BaseModel):
    """Agent-readable conservative judgement for an inspected package."""

    schema_version: str = PACKAGE_JUDGEMENT_SCHEMA_VERSION
    package: str
    version: str | None = None
    decision: AgentDecision
    risk_level: RiskLevel
    confidence: Confidence
    summary: str
    source_availability: SourceAvailability
    installed_size_bytes: int
    detected_capabilities: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    recommendation: str
    evidence: list[str] = Field(default_factory=list)
    capability_exposure_note: str = CAPABILITY_EXPOSURE_NOTE


class TyposquatCandidate(BaseModel):
    """Conservative typosquatting similarity signal for a package name."""

    package: str
    normalized_package: str
    possible_target: str
    matched_reference: str
    similarity: float
    recommendation: str
    signals: list[str] = Field(default_factory=list)
    is_possible_typosquat: bool = False
    evidence: list[str] = Field(default_factory=list)

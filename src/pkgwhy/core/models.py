from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

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


class ToolArtifactType(StrEnum):
    SCRIPT = "script"
    FOLDER = "folder"
    PACKAGE = "package"


class HashStatus(StrEnum):
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    MISSING = "missing"


class ToolRunStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


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
    javascript_files_scanned: int = Field(default=0, ge=0)
    shell_scripts_detected: int = Field(default=0, ge=0)
    native_binaries_detected: int = Field(default=0, ge=0)
    wasm_files_detected: int = Field(default=0, ge=0)
    setup_files_detected: int = Field(default=0, ge=0)


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

    @field_validator("similarity")
    @classmethod
    def validate_similarity(cls, value: float) -> float:
        if not 0 <= value <= 1:
            raise ValueError("similarity must be between 0 and 1")
        return value


class DependencyReason(BaseModel):
    """Project-local evidence explaining why a package may be present."""

    package: str
    normalized_package: str
    status: DependencyStatus
    declared_in: list[str] = Field(default_factory=list)
    lockfiles: list[str] = Field(default_factory=list)
    imported_by_project: bool = False
    installed: bool = False
    transitive_via: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class RegistryConfig(BaseModel):
    """Local registry configuration stored on the user's machine."""

    schema_version: str = "pkgwhy.registry_config.v1"
    current_registry: str | None = None
    registries: dict[str, str] = Field(default_factory=dict)


class RegistryEntry(BaseModel):
    """One configured registry location."""

    name: str
    path: Path
    is_current: bool = False
    index_exists: bool = False


class RegistryToolEntry(BaseModel):
    """One published local tool bundle in a registry index."""

    name: str
    owner: str
    version: str
    artifact_type: ToolArtifactType
    entrypoint: str
    bundle_path: str
    sha256: str
    manifest_path: str
    published_at: str


class RegistryIndex(BaseModel):
    """Local registry index placeholder for published private tools."""

    schema_version: str = "pkgwhy.registry_index.v1"
    tools: list[RegistryToolEntry] = Field(default_factory=list)


class ToolSecurityPolicy(BaseModel):
    """Declared security policy for a private tool manifest."""

    requires_human_approval: bool = True
    allow_unsigned: bool = False
    allow_unpinned_dependencies: bool = False
    signing_status: str = "not_implemented"

    @field_validator("signing_status")
    @classmethod
    def validate_signing_status(cls, value: str) -> str:
        if value != "not_implemented":
            raise ValueError("signing_status must be 'not_implemented' until signing is implemented")
        return value


class ToolAgentPolicy(BaseModel):
    """Declared agent policy for a private tool manifest."""

    default_decision: AgentDecision = AgentDecision.REVIEW_MANUALLY
    non_interactive_decision: AgentDecision = AgentDecision.REVIEW_MANUALLY


class ToolManifest(BaseModel):
    """Validated pkgwhy private tool manifest."""

    schema_version: str = "pkgwhy.tool_manifest.v1"
    name: str
    owner: str
    version: str
    description: str
    artifact_type: ToolArtifactType
    entrypoint: str
    python_requires: str = ">=3.11"
    dependencies: list[str] = Field(default_factory=list)
    declared_permissions: list[str] = Field(default_factory=list)
    security: ToolSecurityPolicy = Field(default_factory=ToolSecurityPolicy)
    agent: ToolAgentPolicy = Field(default_factory=ToolAgentPolicy)

    @field_validator("name", "owner")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9]+([._-][A-Za-z0-9]+)*", value):
            raise ValueError(
                "must start and end with a letter or number, with only single dots, underscores, or hyphens between segments"
            )
        return value

    @field_validator("version", "description", "entrypoint", "python_requires")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("must not be empty")
        return stripped

    @field_validator("dependencies", "declared_permissions")
    @classmethod
    def validate_non_empty_list_items(cls, values: list[str]) -> list[str]:
        stripped_values: list[str] = []
        for value in values:
            stripped = value.strip()
            if not stripped:
                raise ValueError("list values must not be empty")
            stripped_values.append(stripped)
        return stripped_values


class PublishResult(BaseModel):
    """Result of a local-only publish operation."""

    manifest: ToolManifest
    registry_name: str
    registry_path: Path
    bundle_path: Path
    manifest_path: Path
    sha256: str


class ToolJudgement(BaseModel):
    """Agent-readable conservative judgement for a private registry tool."""

    schema_version: str = "pkgwhy.tool_judgement.v1"
    tool: str
    owner: str
    name: str
    version: str
    decision: AgentDecision
    risk_level: RiskLevel
    confidence: Confidence
    reason: str
    requires_human_approval: bool
    manifest: ToolManifest
    declared_permissions: list[str] = Field(default_factory=list)
    detected_capabilities: list[str] = Field(default_factory=list)
    hash_status: HashStatus
    signature_status: str = "not_implemented"
    warnings: list[str] = Field(default_factory=list)
    recommendation: str


class ToolRunResult(BaseModel):
    """Execution metadata for a local private tool run."""

    schema_version: str = "pkgwhy.tool_run.v1"
    tool: str
    owner: str
    name: str
    version: str
    registry_name: str
    registry_path: Path
    command: list[str]
    entrypoint: str
    started_at: str
    finished_at: str
    exit_code: int
    status: ToolRunStatus
    stdout: str
    stderr: str
    log_path: Path
    warning: str

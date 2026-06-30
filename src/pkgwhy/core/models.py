from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from pkgwhy.core.constants import (
    AGENT_PACKAGE_PRECHECK_SCHEMA_VERSION,
    AGENT_POLICY_SCHEMA_VERSION,
    CAPABILITY_EXPOSURE_NOTE,
    DYNAMIC_ANALYSIS_SCHEMA_VERSION,
    PACKAGE_JUDGEMENT_SCHEMA_VERSION,
    PIP_INSTALL_GATE_SCHEMA_VERSION,
    PRECHECK_BATCH_SCHEMA_VERSION,
    PRECHECK_SCHEMA_VERSION,
    RISK_MODEL_VERSION,
)

RiskModelVersion = Literal["pkgwhy.risk_model.v1"]
PrecheckSchemaVersion = Literal["pkgwhy.precheck.v1"]
PrecheckBatchSchemaVersion = Literal["pkgwhy.precheck_batch.v1"]
PipInstallGateSchemaVersion = Literal["pkgwhy.pip_install_gate.v1"]


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


class AgentPolicyConfig(BaseModel):
    """Policy-as-code defaults for non-interactive agent package decisions."""

    schema_version: str = AGENT_POLICY_SCHEMA_VERSION
    allow_public_pypi: bool = False
    allow_unpinned_dependencies: bool = False
    allow_unsigned_tools: bool = False
    require_pkgwhy_judgement: bool = True
    require_hash_verification: bool = True
    require_signature_verification: bool = False
    non_interactive_default_decision: AgentDecision = AgentDecision.BLOCK
    unknown_package_decision: AgentDecision = AgentDecision.REVIEW_MANUALLY
    high_risk_package_decision: AgentDecision = AgentDecision.REVIEW_MANUALLY
    critical_risk_package_decision: AgentDecision = AgentDecision.BLOCK
    non_interactive_unknown_package_decision: AgentDecision = AgentDecision.BLOCK
    non_interactive_high_risk_package_decision: AgentDecision = AgentDecision.BLOCK
    non_interactive_critical_risk_package_decision: AgentDecision = AgentDecision.BLOCK
    tool_execution_requires_local_registry: bool = True
    dynamic_analysis_default_decision: AgentDecision = AgentDecision.BLOCK


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


class DynamicAnalysisStatus(StrEnum):
    BLOCKED = "blocked"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    COMPLETED = "completed"
    FAILED = "failed"


class DynamicNetworkMode(StrEnum):
    OFF = "off"


class DynamicFilesystemMode(StrEnum):
    SCRATCH = "scratch"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RuleSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleCategory(StrEnum):
    VULNERABILITY = "vulnerability"
    IDENTITY = "identity"
    SOURCE = "source"
    METADATA = "metadata"
    STATIC_ANALYSIS = "static_analysis"
    BINARY = "binary"
    POLICY = "policy"


class DependencyStatus(StrEnum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    IMPORTED_BY_PROJECT = "imported_by_project"
    NOT_INSTALLED = "not_installed"
    UNKNOWN = "unknown"


class SourceAvailability(StrEnum):
    INSTALLED_SOURCE_PRESENT = "installed_source_present"
    ARTIFACT_SOURCE_PRESENT = "artifact_source_present"
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


class VulnerabilityRange(BaseModel):
    """Conservative affected-version range parsed from advisory data."""

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None
    range_type: str | None = None


class VulnerabilityRecord(BaseModel):
    """Source-attributed vulnerability advisory record."""

    id: str
    aliases: list[str] = Field(default_factory=list)
    package_name: str
    ecosystem: str | None = None
    summary: str | None = None
    details: str | None = None
    severity: list[str] = Field(default_factory=list)
    affected_ranges: list[VulnerabilityRange] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    source: str
    source_url: str | None = None


class VulnerabilityMatch(BaseModel):
    """A conservative package-version match against a vulnerability record."""

    vulnerability_id: str
    package: str
    version: str
    aliases: list[str] = Field(default_factory=list)
    summary: str | None = None
    severity: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    source: str
    source_url: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[str] = Field(default_factory=list)


class PackageProvenance(BaseModel):
    """Metadata-derived source-trust signals without claiming unavailable attestations."""

    package: str
    version: str | None = None
    repository_url: str | None = None
    documentation_url: str | None = None
    homepage_url: str | None = None
    project_urls: dict[str, str] = Field(default_factory=dict)
    metadata_source: str = "unknown"
    source_distribution_status: str = "unknown"
    trusted_publishing_status: str = "unknown"
    attestation_status: str = "not_implemented"
    release_activity_status: str = "unknown"
    confidence: Confidence = Confidence.LOW
    warnings: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class RiskRuleEvidence(BaseModel):
    """One versioned risk-rule contribution to a package judgement."""

    rule_id: str
    name: str
    category: RuleCategory
    severity: RuleSeverity
    confidence: Confidence
    message: str
    evidence: list[str] = Field(default_factory=list)
    file_path: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    symbol: str | None = None
    false_positive_note: str | None = None


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
    rule_evidence: list[RiskRuleEvidence] = Field(default_factory=list)
    files_scanned: int = 0


class FileStaticAnalysis(BaseModel):
    """Static file-type and text-pattern signals gathered without execution."""

    detected_capabilities: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    rule_evidence: list[RiskRuleEvidence] = Field(default_factory=list)
    url_references: list[str] = Field(default_factory=list)
    domain_references: list[str] = Field(default_factory=list)
    credential_references: list[str] = Field(default_factory=list)
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
    rule_evidence: list[RiskRuleEvidence] = Field(default_factory=list)
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
    risk_model_version: RiskModelVersion = RISK_MODEL_VERSION
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
    risk_rules: list[RiskRuleEvidence] = Field(default_factory=list)
    known_vulnerabilities: list[VulnerabilityMatch] = Field(default_factory=list)
    provenance: PackageProvenance | None = None
    capability_exposure_note: str = CAPABILITY_EXPOSURE_NOTE


class AgentPackagePrecheckResult(BaseModel):
    """Schema-versioned agent policy decision for one package judgement."""

    schema_version: str = AGENT_PACKAGE_PRECHECK_SCHEMA_VERSION
    policy_schema_version: str = AGENT_POLICY_SCHEMA_VERSION
    package: str
    version: str | None = None
    target_type: Literal["package"] = "package"
    non_interactive: bool = True
    decision: AgentDecision
    risk_level: RiskLevel
    confidence: Confidence
    policy_decision_source: str
    reasons: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    recommendation: str
    package_judgement: PackageJudgement


class PrecheckSignalSummary(BaseModel):
    """Compact summary of one evidence source used by pre-install precheck."""

    status: str
    sources: list[str] = Field(default_factory=list)
    match_count: int = Field(default=0, ge=0)
    warning_count: int = Field(default=0, ge=0)
    warnings: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class PrecheckArtifactSummary(BaseModel):
    """Summary of optional downloaded artifact inspection."""

    status: str = "not_requested"
    filename: str | None = None
    package_type: str | None = None
    url: str | None = None
    sha256_status: str = "not_checked"
    size_bytes: int = Field(default=0, ge=0)
    extracted_file_count: int = Field(default=0, ge=0)
    kept_path: str | None = None
    warnings: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class PreInstallPackagePrecheckResult(BaseModel):
    """Schema-versioned pre-install package gate result."""

    schema_version: PrecheckSchemaVersion = PRECHECK_SCHEMA_VERSION
    target_type: Literal["package"] = "package"
    requested: str
    package: str
    normalized_package: str
    requested_specifier: str | None = None
    requested_version: str | None = None
    version: str | None = None
    metadata_source: str
    lookup_status: str
    network_requested: bool = False
    artifacts_downloaded: bool = False
    decision: AgentDecision
    exit_code: int = Field(default=0, ge=0)
    risk_level: RiskLevel
    confidence: Confidence
    policy_decision: AgentDecision
    policy_reasons: list[str] = Field(default_factory=list)
    summary: str
    recommendation: str
    warnings: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    vulnerability_summary: PrecheckSignalSummary
    provenance_summary: PrecheckSignalSummary
    typosquat_summary: PrecheckSignalSummary
    static_summary: PrecheckSignalSummary
    artifact_summary: PrecheckArtifactSummary = Field(default_factory=PrecheckArtifactSummary)
    package_judgement: PackageJudgement


class PrecheckBatchResult(BaseModel):
    """Schema-versioned pre-install gate result for dependency declaration files."""

    schema_version: PrecheckBatchSchemaVersion = PRECHECK_BATCH_SCHEMA_VERSION
    target_type: Literal["requirements", "pyproject"]
    source: str
    package_count: int = Field(ge=0)
    decision: AgentDecision
    exit_code: int = Field(default=0, ge=0)
    risk_level: RiskLevel
    confidence: Confidence
    warnings: list[str] = Field(default_factory=list)
    results: list[PreInstallPackagePrecheckResult] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_package_count(self) -> PrecheckBatchResult:
        if self.package_count != len(self.results):
            raise ValueError("package_count must match number of precheck results")
        return self


class PipInstallGateResult(BaseModel):
    """Schema-versioned result for the pip install gate."""

    schema_version: PipInstallGateSchemaVersion = PIP_INSTALL_GATE_SCHEMA_VERSION
    target_type: Literal["package", "requirements"]
    requested: list[str] = Field(default_factory=list)
    requirement_file: str | None = None
    policy: Literal["standard", "strict"] = "standard"
    decision: AgentDecision
    risk_level: RiskLevel
    confidence: Confidence
    precheck_exit_code: int = Field(ge=0)
    exit_code: int = Field(ge=0)
    pip_invoked: bool = False
    pip_command: list[str] = Field(default_factory=list)
    pip_returncode: int | None = None
    dry_run: bool = False
    override_used: bool = False
    override_reason: str | None = None
    log_path: str | None = None
    reasons: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    precheck: PreInstallPackagePrecheckResult | PrecheckBatchResult


class DynamicProcessEvent(BaseModel):
    """Observed process event from a dynamic backend."""

    command: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    duration_ms: int | None = Field(default=None, ge=0)


class DynamicFilesystemEvent(BaseModel):
    """Observed filesystem event from a dynamic backend."""

    path: str
    action: str


class DynamicNetworkEvent(BaseModel):
    """Observed network event from a dynamic backend."""

    destination: str
    action: str
    protocol: str | None = None


class DynamicAnalysisResult(BaseModel):
    """Schema-versioned dynamic analysis result without fabricated events."""

    schema_version: str = DYNAMIC_ANALYSIS_SCHEMA_VERSION
    target: str
    mode: str = "inspect"
    sandbox_backend: str
    network_mode: DynamicNetworkMode = DynamicNetworkMode.OFF
    filesystem_mode: DynamicFilesystemMode = DynamicFilesystemMode.SCRATCH
    status: DynamicAnalysisStatus
    warnings: list[str] = Field(default_factory=list)
    process_events: list[DynamicProcessEvent] = Field(default_factory=list)
    filesystem_events: list[DynamicFilesystemEvent] = Field(default_factory=list)
    network_events: list[DynamicNetworkEvent] = Field(default_factory=list)
    decision: AgentDecision
    limitations: list[str] = Field(default_factory=list)


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
    """Result of a local registry publish operation."""

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
    policy_decision: AgentDecision
    policy_reasons: list[str] = Field(default_factory=list)
    policy_warnings: list[str] = Field(default_factory=list)

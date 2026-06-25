from __future__ import annotations

from dataclasses import dataclass

from pkgwhy.core.models import Confidence, RiskRuleEvidence, RuleCategory, RuleSeverity


@dataclass(frozen=True)
class RuleDefinition:
    """Stable metadata for one pre-alpha risk rule."""

    rule_id: str
    name: str
    category: RuleCategory
    severity: RuleSeverity
    confidence: Confidence
    default_message: str
    false_positive_note: str | None = None


RULES: dict[str, RuleDefinition] = {
    "PKGWHY-VULN-001": RuleDefinition(
        rule_id="PKGWHY-VULN-001",
        name="known_vulnerability_match",
        category=RuleCategory.VULNERABILITY,
        severity=RuleSeverity.HIGH,
        confidence=Confidence.MEDIUM,
        default_message="Known vulnerability advisory matched this package version.",
        false_positive_note="Advisory databases can be incomplete or imprecise; verify the source advisory and version range.",
    ),
    "PKGWHY-RISK-001": RuleDefinition(
        rule_id="PKGWHY-RISK-001",
        name="possible_typosquat_similarity",
        category=RuleCategory.IDENTITY,
        severity=RuleSeverity.MEDIUM,
        confidence=Confidence.MEDIUM,
        default_message="Package name is similar to a popular package name.",
        false_positive_note="Legitimate ecosystem packages can share prefixes or naming families.",
    ),
    "PKGWHY-RISK-002": RuleDefinition(
        rule_id="PKGWHY-RISK-002",
        name="source_availability_unknown",
        category=RuleCategory.SOURCE,
        severity=RuleSeverity.MEDIUM,
        confidence=Confidence.MEDIUM,
        default_message="Source availability is unknown from installed files.",
        false_positive_note="Some legitimate packages ship metadata-only wheels or generated artifacts.",
    ),
    "PKGWHY-RISK-003": RuleDefinition(
        rule_id="PKGWHY-RISK-003",
        name="missing_license_metadata",
        category=RuleCategory.METADATA,
        severity=RuleSeverity.MEDIUM,
        confidence=Confidence.MEDIUM,
        default_message="Installed metadata does not include a clear license value.",
        false_positive_note="License metadata can be omitted even when licensing is documented elsewhere.",
    ),
    "PKGWHY-RISK-004": RuleDefinition(
        rule_id="PKGWHY-RISK-004",
        name="native_compiled_code_present",
        category=RuleCategory.BINARY,
        severity=RuleSeverity.MEDIUM,
        confidence=Confidence.MEDIUM,
        default_message="Native compiled files are present.",
        false_positive_note="Native extensions are common in legitimate numerical, cryptographic, and performance packages.",
    ),
    "PKGWHY-RISK-005": RuleDefinition(
        rule_id="PKGWHY-RISK-005",
        name="static_capability_signal",
        category=RuleCategory.STATIC_ANALYSIS,
        severity=RuleSeverity.MEDIUM,
        confidence=Confidence.MEDIUM,
        default_message="Static capability signal detected.",
        false_positive_note="Static references are not proof of runtime behavior, intent, or unsafe use.",
    ),
    "PKGWHY-RISK-006": RuleDefinition(
        rule_id="PKGWHY-RISK-006",
        name="no_installed_files_found",
        category=RuleCategory.METADATA,
        severity=RuleSeverity.HIGH,
        confidence=Confidence.LOW,
        default_message="No installed package files were found through distribution metadata.",
        false_positive_note="Editable installs or unusual packaging layouts can hide files from distribution metadata.",
    ),
}


def make_rule_evidence(
    rule_id: str,
    *,
    message: str | None = None,
    evidence: list[str] | None = None,
    severity: RuleSeverity | None = None,
    confidence: Confidence | None = None,
    file_path: str | None = None,
    line_number: int | None = None,
    symbol: str | None = None,
) -> RiskRuleEvidence:
    definition = RULES[rule_id]
    return RiskRuleEvidence(
        rule_id=definition.rule_id,
        name=definition.name,
        category=definition.category,
        severity=severity or definition.severity,
        confidence=confidence or definition.confidence,
        message=message or definition.default_message,
        evidence=evidence or [],
        file_path=file_path,
        line_number=line_number,
        symbol=symbol,
        false_positive_note=definition.false_positive_note,
    )

from __future__ import annotations

from pkgwhy.core.models import (
    AgentDecision,
    Confidence,
    PackageInspection,
    PackageJudgement,
    RiskRuleEvidence,
    RiskLevel,
    RuleSeverity,
    SourceAvailability,
    VulnerabilityMatch,
)
from pkgwhy.provenance.installed import assess_installed_provenance
from pkgwhy.typosquat.detector import detect_typosquat


def judge_inspection(
    inspection: PackageInspection,
    known_vulnerabilities: list[VulnerabilityMatch] | None = None,
) -> PackageJudgement:
    metadata = inspection.metadata
    warnings = list(inspection.warnings)
    evidence = list(inspection.evidence)
    risk_rules: list[RiskRuleEvidence] = []
    known_vulnerabilities = known_vulnerabilities or []
    risk = RiskLevel.LOW
    confidence = Confidence.MEDIUM
    provenance = assess_installed_provenance(metadata)

    for vulnerability in known_vulnerabilities:
        fixed = f" Fixed versions: {', '.join(vulnerability.fixed_versions)}." if vulnerability.fixed_versions else ""
        message = (
            f"Known vulnerability match: {vulnerability.vulnerability_id} from {vulnerability.source}. "
            "This result depends on the supplied vulnerability source and may be incomplete."
            f"{fixed}"
        )
        warnings.append(message)
        evidence.extend(vulnerability.evidence)
        risk_rules.append(
            RiskRuleEvidence(
                rule_id="PKGWHY-VULN-001",
                name="known_vulnerability_match",
                severity=_severity_for_vulnerability(vulnerability),
                confidence=vulnerability.confidence,
                message=message,
                evidence=vulnerability.evidence,
            )
        )
        risk = _raise_risk(risk, _risk_for_vulnerability(vulnerability))

    typosquat_candidate = detect_typosquat(metadata.identity.name)
    if typosquat_candidate is not None:
        message = (
            "Possible typosquatting risk: "
            f"'{metadata.identity.name}' is similar to popular package '{typosquat_candidate.possible_target}'. "
            "This is a signal, not proof of unsafe behavior."
        )
        warnings.append(message)
        evidence.extend(typosquat_candidate.evidence)
        risk_rules.append(
            RiskRuleEvidence(
                rule_id="PKGWHY-RISK-001",
                name="possible_typosquat_similarity",
                severity=RuleSeverity.MEDIUM,
                confidence=Confidence.MEDIUM,
                message=message,
                evidence=typosquat_candidate.evidence,
            )
        )
        risk = _raise_risk(risk, RiskLevel.MEDIUM)

    if inspection.source_availability in {
        SourceAvailability.SOURCE_AVAILABILITY_UNKNOWN,
        SourceAvailability.INSTALLED_METADATA_ONLY,
    }:
        message = "Source availability is unknown from installed files."
        warnings.append(message)
        risk_rules.append(
            RiskRuleEvidence(
                rule_id="PKGWHY-RISK-002",
                name="source_availability_unknown",
                severity=RuleSeverity.MEDIUM,
                confidence=Confidence.MEDIUM,
                message=message,
                evidence=["Installed file metadata did not provide readable source paths."],
            )
        )
        risk = _raise_risk(risk, RiskLevel.MEDIUM)

    if not metadata.license:
        message = "Installed metadata does not include a clear license value."
        warnings.append(message)
        risk_rules.append(
            RiskRuleEvidence(
                rule_id="PKGWHY-RISK-003",
                name="missing_license_metadata",
                severity=RuleSeverity.MEDIUM,
                confidence=Confidence.MEDIUM,
                message=message,
                evidence=["License metadata field was empty."],
            )
        )
        risk = _raise_risk(risk, RiskLevel.MEDIUM)

    if "Native compiled code present" in inspection.detected_capabilities:
        message = "Native compiled files are present. This can be legitimate, but static review is more limited."
        warnings.append(message)
        risk_rules.append(
            RiskRuleEvidence(
                rule_id="PKGWHY-RISK-004",
                name="native_compiled_code_present",
                severity=RuleSeverity.MEDIUM,
                confidence=Confidence.MEDIUM,
                message=message,
                evidence=["Installed file scan detected native binary file extensions."],
            )
        )
        risk = _raise_risk(risk, RiskLevel.MEDIUM)

    for capability in _warning_capability_signals(inspection.detected_capabilities):
        message = f"Static capability signal detected: {capability}. This is not proof of unsafe behavior."
        warnings.append(message)
        risk_rules.append(
            RiskRuleEvidence(
                rule_id="PKGWHY-RISK-005",
                name="static_capability_signal",
                severity=RuleSeverity.MEDIUM,
                confidence=Confidence.MEDIUM,
                message=message,
                evidence=[f"Detected capability signal: {capability}."],
            )
        )
        risk = _raise_risk(risk, RiskLevel.MEDIUM)

    if inspection.size.file_count == 0:
        message = "No installed package files were found through distribution metadata."
        warnings.append(message)
        risk_rules.append(
            RiskRuleEvidence(
                rule_id="PKGWHY-RISK-006",
                name="no_installed_files_found",
                severity=RuleSeverity.HIGH,
                confidence=Confidence.LOW,
                message=message,
                evidence=["Distribution metadata did not expose files for static inspection."],
            )
        )
        if risk not in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            risk = RiskLevel.UNKNOWN
            confidence = Confidence.LOW

    decision = _decision_for_risk(risk)
    recommendation = _recommendation_for_risk(risk)
    summary = metadata.summary or "No installed summary is available for this package."

    return PackageJudgement(
        package=metadata.identity.name,
        version=metadata.identity.version,
        decision=decision,
        risk_level=risk,
        confidence=confidence,
        summary=summary,
        source_availability=inspection.source_availability,
        installed_size_bytes=inspection.size.total_bytes,
        detected_capabilities=inspection.detected_capabilities,
        warnings=sorted(set(warnings)),
        recommendation=recommendation,
        evidence=evidence,
        risk_rules=risk_rules,
        known_vulnerabilities=known_vulnerabilities,
        provenance=provenance,
    )


def _warning_capability_signals(capabilities: list[str]) -> list[str]:
    warning_signals = {
        "Subprocess or shell execution signals",
        "Dynamic code execution signals",
        "JavaScript dynamic code execution signals",
        "JavaScript obfuscation signals",
        "Encoded payload handling signals",
        "Deserialisation risk signals",
        "Credential or token access patterns",
        "Package manager manipulation signals",
        "Shell script files present",
        "Install-time setup files present",
        "WASM binary code present",
    }
    return sorted(set(capabilities) & warning_signals)


def _decision_for_risk(risk: RiskLevel) -> AgentDecision:
    if risk == RiskLevel.LOW:
        return AgentDecision.ALLOW
    if risk == RiskLevel.MEDIUM:
        return AgentDecision.ALLOW_WITH_CAUTION
    if risk == RiskLevel.HIGH:
        return AgentDecision.REVIEW_MANUALLY
    if risk == RiskLevel.CRITICAL:
        return AgentDecision.BLOCK
    if risk == RiskLevel.UNKNOWN:
        return AgentDecision.REVIEW_MANUALLY
    return AgentDecision.REVIEW_MANUALLY


def _recommendation_for_risk(risk: RiskLevel) -> str:
    if risk == RiskLevel.LOW:
        return "Allow for normal use in trusted projects, while keeping normal dependency review practices."
    if risk == RiskLevel.MEDIUM:
        return "Allow with caution. Review the listed signals before agent or production use."
    if risk == RiskLevel.HIGH:
        return "Manual review recommended before installation, import, or execution."
    if risk == RiskLevel.CRITICAL:
        return "Block for AI-agent usage unless a human explicitly approves after review."
    if risk == RiskLevel.UNKNOWN:
        return "Risk is unknown. Manual review recommended."
    return "Risk is unknown. Manual review recommended."


def _raise_risk(current: RiskLevel, candidate: RiskLevel) -> RiskLevel:
    order = {
        RiskLevel.LOW: 0,
        RiskLevel.MEDIUM: 1,
        RiskLevel.HIGH: 2,
        RiskLevel.CRITICAL: 3,
        RiskLevel.UNKNOWN: 1,
    }
    return candidate if order[candidate] > order[current] else current


def _risk_for_vulnerability(vulnerability: VulnerabilityMatch) -> RiskLevel:
    severity = " ".join(vulnerability.severity).lower()
    if "critical" in severity:
        return RiskLevel.CRITICAL
    return RiskLevel.HIGH


def _severity_for_vulnerability(vulnerability: VulnerabilityMatch) -> RuleSeverity:
    severity = " ".join(vulnerability.severity).lower()
    if "critical" in severity:
        return RuleSeverity.CRITICAL
    if "high" in severity:
        return RuleSeverity.HIGH
    return RuleSeverity.HIGH

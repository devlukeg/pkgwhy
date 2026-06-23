from __future__ import annotations

from pkgwhy.core.models import (
    AgentDecision,
    Confidence,
    PackageInspection,
    PackageJudgement,
    RiskLevel,
    SourceAvailability,
)
from pkgwhy.typosquat.detector import detect_typosquat


def judge_inspection(inspection: PackageInspection) -> PackageJudgement:
    metadata = inspection.metadata
    warnings = list(inspection.warnings)
    evidence = list(inspection.evidence)
    risk = RiskLevel.LOW
    confidence = Confidence.MEDIUM
    typosquat_candidate = detect_typosquat(metadata.identity.name)
    if typosquat_candidate is not None:
        warnings.append(
            "Possible typosquatting risk: "
            f"'{metadata.identity.name}' is similar to popular package '{typosquat_candidate.possible_target}'. "
            "This is a signal, not proof of unsafe behavior."
        )
        evidence.extend(typosquat_candidate.evidence)
        if risk == RiskLevel.LOW:
            risk = RiskLevel.MEDIUM

    if inspection.source_availability in {
        SourceAvailability.SOURCE_AVAILABILITY_UNKNOWN,
        SourceAvailability.INSTALLED_METADATA_ONLY,
    }:
        warnings.append("Source availability is unknown from installed files.")
        risk = RiskLevel.MEDIUM

    if not metadata.license:
        warnings.append("Installed metadata does not include a clear license value.")
        if risk == RiskLevel.LOW:
            risk = RiskLevel.MEDIUM

    if "Native compiled code present" in inspection.detected_capabilities:
        warnings.append("Native compiled files are present. This can be legitimate, but static review is more limited.")
        if risk == RiskLevel.LOW:
            risk = RiskLevel.MEDIUM

    for capability in _warning_capability_signals(inspection.detected_capabilities):
        warnings.append(f"Static capability signal detected: {capability}. This is not proof of unsafe behavior.")
        if risk == RiskLevel.LOW:
            risk = RiskLevel.MEDIUM

    if inspection.size.file_count == 0:
        warnings.append("No installed package files were found through distribution metadata.")
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

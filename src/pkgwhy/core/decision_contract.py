from __future__ import annotations

from typing import Any, Iterable, Sequence

EXIT_CODE_MEANINGS: dict[int, str] = {
    0: "allowed or completed successfully",
    1: "review or caution required before proceeding",
    2: "blocked by policy or risk decision",
    3: "tool, configuration, or user input error",
    4: "external data unavailable or evidence incomplete",
}

DECISION_ORDER: dict[str, int] = {
    "allow": 0,
    "allow_with_caution": 1,
    "review_manually": 2,
    "sandbox_only": 3,
    "block": 4,
}

RISK_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "unknown": 1,
    "high": 2,
    "critical": 3,
}

CONFIDENCE_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
}

SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def value_text(value: Any) -> str:
    enum_value = getattr(value, "value", None)
    if isinstance(enum_value, str):
        return enum_value
    return str(value)


def exit_code_meaning(exit_code: int) -> str:
    return EXIT_CODE_MEANINGS.get(exit_code, "unclassified exit status")


def exit_code_for_decision(decision: Any) -> int:
    decision_text = value_text(decision)
    if decision_text == "allow":
        return 0
    if decision_text in {"allow_with_caution", "review_manually"}:
        return 1
    if decision_text in {"sandbox_only", "block"}:
        return 2
    return 3


def recommended_next_action(decision: Any, fallback: str | None = None) -> str:
    decision_text = value_text(decision)
    if decision_text == "allow":
        return fallback or "Proceed under normal dependency review practices."
    if decision_text == "allow_with_caution":
        return fallback or "Review warnings and evidence before installing, importing, or running."
    if decision_text == "review_manually":
        return fallback or "Ask a human to review the evidence before proceeding."
    if decision_text == "sandbox_only":
        return fallback or "Use only inside a real sandbox; a Python virtual environment is not a full OS sandbox."
    if decision_text == "block":
        return fallback or "Do not install, import, or run unless a human approves a policy exception."
    return fallback or "Review the result before proceeding."


def strictest_decision(decisions: Iterable[Any]) -> str:
    decision_values = [value_text(decision) for decision in decisions]
    if not decision_values:
        return "review_manually"
    return max(decision_values, key=lambda decision: DECISION_ORDER.get(decision, 2))


def highest_risk(risks: Iterable[Any]) -> str:
    risk_values = [value_text(risk) for risk in risks]
    if not risk_values:
        return "unknown"
    return max(risk_values, key=lambda risk: RISK_ORDER.get(risk, 1))


def lowest_confidence(confidences: Iterable[Any]) -> str:
    confidence_values = [value_text(confidence) for confidence in confidences]
    if not confidence_values:
        return "low"
    return min(confidence_values, key=lambda confidence: CONFIDENCE_ORDER.get(confidence, 0))


def compact_evidence_summary(
    *,
    evidence: Sequence[str] | None = None,
    warnings: Sequence[str] | None = None,
    risk_rules: Sequence[Any] | None = None,
    top_evidence_limit: int = 5,
    top_warning_limit: int = 3,
    top_rule_limit: int = 5,
) -> dict[str, object]:
    evidence_items = list(evidence or [])
    warning_items = list(warnings or [])
    rules = list(risk_rules or [])
    severities = [value_text(getattr(rule, "severity", "")) for rule in rules]
    highest_severity = max(severities, key=lambda severity: SEVERITY_ORDER.get(severity, -1), default=None)
    return {
        "evidence_count": len(evidence_items),
        "warning_count": len(warning_items),
        "top_evidence": evidence_items[:top_evidence_limit],
        "top_warnings": warning_items[:top_warning_limit],
        "risk_rule_count": len(rules),
        "top_risk_rule_ids": [
            rule_id
            for rule_id in (getattr(rule, "rule_id", None) for rule in rules[:top_rule_limit])
            if isinstance(rule_id, str)
        ],
        "highest_rule_severity": highest_severity,
    }


def source_freshness_for_precheck(*, metadata_source: str, lookup_status: str, network_requested: bool) -> str:
    if network_requested:
        return f"external_lookup_requested:{lookup_status}"
    if metadata_source == "installed_distribution_metadata":
        return "local_installed_distribution_metadata"
    if metadata_source == "pypi_json":
        return f"pypi_project_json:{lookup_status}"
    if metadata_source == "unavailable":
        return "no_current_source_available"
    return f"{metadata_source}:{lookup_status}"

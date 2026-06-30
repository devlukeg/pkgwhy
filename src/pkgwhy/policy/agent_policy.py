from __future__ import annotations

from pkgwhy.core.models import (
    AgentDecision,
    AgentPackagePrecheckResult,
    AgentPolicyConfig,
    PackageJudgement,
    RiskLevel,
)

NON_INTERACTIVE_PACKAGE_ALLOWED_DECISIONS = {AgentDecision.ALLOW, AgentDecision.ALLOW_WITH_CAUTION}


def default_agent_policy() -> AgentPolicyConfig:
    """Return conservative default policy settings for agent package decisions."""

    return AgentPolicyConfig()


def evaluate_package_policy(
    judgement: PackageJudgement,
    *,
    non_interactive: bool = True,
    policy: AgentPolicyConfig | None = None,
) -> AgentPackagePrecheckResult:
    """Apply policy-as-code to a package judgement without changing the judgement itself."""

    active_policy = policy or default_agent_policy()
    decision = judgement.decision
    reasons: list[str] = []
    warnings = list(judgement.warnings)
    decision_source = "package_judgement"

    risk_policy_decision = _decision_for_risk(judgement.risk_level, active_policy, non_interactive=non_interactive)
    if risk_policy_decision is not None:
        decision = _stricter_decision(decision, risk_policy_decision)
        decision_source = "agent_policy"
        reasons.append(_risk_policy_reason(judgement.risk_level, non_interactive=non_interactive))

    if non_interactive and judgement.decision not in NON_INTERACTIVE_PACKAGE_ALLOWED_DECISIONS:
        decision = _stricter_decision(decision, active_policy.non_interactive_default_decision)
        decision_source = "agent_policy"
        reasons.append(f"Non-interactive package use is not allowed for decision: {judgement.decision.value}.")

    if active_policy.require_pkgwhy_judgement and not judgement.evidence:
        decision = _stricter_decision(decision, AgentDecision.REVIEW_MANUALLY)
        decision_source = "agent_policy"
        reasons.append("Policy requires a pkgwhy judgement with supporting evidence.")

    recommendation = _recommendation_for_decision(decision, judgement.recommendation, non_interactive=non_interactive)
    return AgentPackagePrecheckResult(
        package=judgement.package,
        version=judgement.version,
        non_interactive=non_interactive,
        decision=decision,
        risk_level=judgement.risk_level,
        confidence=judgement.confidence,
        policy_decision_source=decision_source,
        reasons=reasons,
        warnings=warnings,
        recommendation=recommendation,
        package_judgement=judgement,
    )


def _decision_for_risk(
    risk_level: RiskLevel,
    policy: AgentPolicyConfig,
    *,
    non_interactive: bool,
) -> AgentDecision | None:
    if risk_level == RiskLevel.UNKNOWN:
        return (
            policy.non_interactive_unknown_package_decision
            if non_interactive
            else policy.unknown_package_decision
        )
    if risk_level == RiskLevel.HIGH:
        return policy.non_interactive_high_risk_package_decision if non_interactive else policy.high_risk_package_decision
    if risk_level == RiskLevel.CRITICAL:
        return (
            policy.non_interactive_critical_risk_package_decision
            if non_interactive
            else policy.critical_risk_package_decision
        )
    return None


def _risk_policy_reason(risk_level: RiskLevel, *, non_interactive: bool) -> str:
    mode = "non-interactive agent use" if non_interactive else "agent use"
    return f"Policy requires a stricter decision for {risk_level.value}-risk packages in {mode}."


def _stricter_decision(current: AgentDecision, candidate: AgentDecision) -> AgentDecision:
    order = {
        AgentDecision.ALLOW: 0,
        AgentDecision.ALLOW_WITH_CAUTION: 1,
        AgentDecision.REVIEW_MANUALLY: 2,
        AgentDecision.SANDBOX_ONLY: 3,
        AgentDecision.BLOCK: 4,
    }
    return candidate if order[candidate] > order[current] else current


def _recommendation_for_decision(decision: AgentDecision, fallback: str, *, non_interactive: bool) -> str:
    if decision == AgentDecision.BLOCK:
        if non_interactive:
            return "Block non-interactive package use until a human reviews the judgement evidence."
        return "Block package use until a human reviews the evidence."
    if decision == AgentDecision.REVIEW_MANUALLY:
        return "Manual review is required before an agent uses this package."
    if decision == AgentDecision.SANDBOX_ONLY:
        return "Use only in a real sandboxed environment; a Python virtual environment is not a full OS sandbox."
    return fallback

from __future__ import annotations

from dataclasses import dataclass, field

from pkgwhy.core.models import AgentDecision, HashStatus, ToolJudgement, ToolTrustState

SIGNATURE_STATUS_VERIFIED = "verified"
SIGNATURE_STATUS_NOT_IMPLEMENTED = "not_implemented"


@dataclass(frozen=True)
class ToolExecutionPolicy:
    """Conservative local execution policy for private registry tools."""

    allow_unsigned_tools: bool = False
    allow_unpinned_dependencies: bool = False
    require_hash_verification: bool = True
    require_signature_verification: bool = False


@dataclass(frozen=True)
class ToolExecutionPolicyResult:
    """Policy decision used before local private-tool execution."""

    allowed: bool
    decision: AgentDecision
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


NON_INTERACTIVE_ALLOWED_DECISIONS = {AgentDecision.ALLOW, AgentDecision.ALLOW_WITH_CAUTION}


def evaluate_tool_execution_policy(
    judgement: ToolJudgement,
    *,
    non_interactive: bool = False,
    policy: ToolExecutionPolicy | None = None,
) -> ToolExecutionPolicyResult:
    active_policy = policy or ToolExecutionPolicy()
    reasons: list[str] = []
    warnings: list[str] = []

    if active_policy.require_hash_verification and judgement.hash_status != HashStatus.VERIFIED:
        reasons.append(f"Tool bundle hash is not verified: {judgement.hash_status.value}.")

    if judgement.trust_state in {ToolTrustState.QUARANTINED, ToolTrustState.BLOCKED}:
        reasons.append(f"Registry trust state blocks execution: {judgement.trust_state.value}.")
    elif judgement.trust_state == ToolTrustState.UNKNOWN:
        warnings.append("Registry trust state is unknown; manual review is recommended before execution.")

    if judgement.decision == AgentDecision.BLOCK:
        reasons.append("Tool judgement blocks execution.")
    elif judgement.decision == AgentDecision.SANDBOX_ONLY:
        reasons.append("Tool requires sandbox-only execution, but the local runner is not a full OS sandbox.")

    if judgement.signature_status != SIGNATURE_STATUS_VERIFIED:
        message = "Tool signature verification is not implemented; treat this tool as unsigned."
        if active_policy.require_signature_verification:
            reasons.append(message)
        elif not active_policy.allow_unsigned_tools:
            warnings.append(message)

    if judgement.manifest.dependencies:
        if active_policy.allow_unpinned_dependencies:
            warnings.append("Tool dependencies are declared, but dependency installation is not implemented in the runner.")
        else:
            reasons.append("Dependency installation is not implemented for tools with declared dependencies.")

    if non_interactive:
        if judgement.decision not in NON_INTERACTIVE_ALLOWED_DECISIONS:
            reasons.append(f"Non-interactive execution is not allowed for judgement decision: {judgement.decision.value}.")
        if judgement.manifest.agent.non_interactive_decision not in NON_INTERACTIVE_ALLOWED_DECISIONS:
            reasons.append(
                "Manifest agent policy does not allow non-interactive execution: "
                f"{judgement.manifest.agent.non_interactive_decision.value}."
            )

    allowed = not reasons
    decision = AgentDecision.BLOCK if reasons else (AgentDecision.REVIEW_MANUALLY if warnings else judgement.decision)
    return ToolExecutionPolicyResult(allowed=allowed, decision=decision, reasons=reasons, warnings=warnings)

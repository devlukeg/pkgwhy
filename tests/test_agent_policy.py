from pkgwhy.core.models import (
    AgentDecision,
    AgentPackagePrecheckResult,
    AgentPolicyConfig,
    Confidence,
    PackageJudgement,
    RiskLevel,
    SourceAvailability,
)
from pkgwhy.policy.agent_policy import default_agent_policy, evaluate_package_policy


def _judgement(
    *,
    risk_level: RiskLevel,
    decision: AgentDecision,
    evidence: list[str] | None = None,
) -> PackageJudgement:
    return PackageJudgement(
        package="demo-package",
        version="1.0.0",
        decision=decision,
        risk_level=risk_level,
        confidence=Confidence.MEDIUM,
        summary="Synthetic package judgement for policy tests.",
        source_availability=SourceAvailability.INSTALLED_SOURCE_PRESENT,
        installed_size_bytes=1,
        recommendation="Existing package recommendation.",
        evidence=["Static package judgement evidence."] if evidence is None else evidence,
    )


def test_default_agent_policy_is_schema_versioned_and_conservative() -> None:
    policy = default_agent_policy()

    assert policy.schema_version == "pkgwhy.agent_policy.v1"
    assert policy.allow_public_pypi is False
    assert policy.allow_unpinned_dependencies is False
    assert policy.allow_unsigned_tools is False
    assert policy.require_pkgwhy_judgement is True
    assert policy.non_interactive_default_decision == AgentDecision.BLOCK
    assert policy.non_interactive_unknown_package_decision == AgentDecision.BLOCK
    assert policy.non_interactive_high_risk_package_decision == AgentDecision.BLOCK
    assert policy.non_interactive_critical_risk_package_decision == AgentDecision.BLOCK


def test_non_interactive_unknown_package_is_blocked() -> None:
    result = evaluate_package_policy(
        _judgement(risk_level=RiskLevel.UNKNOWN, decision=AgentDecision.REVIEW_MANUALLY),
        non_interactive=True,
    )

    AgentPackagePrecheckResult.model_validate(result.model_dump(mode="json"))
    assert result.schema_version == "pkgwhy.agent_package_precheck.v1"
    assert result.command == "pkgwhy agent precheck"
    assert result.target == "demo-package"
    assert result.policy_schema_version == "pkgwhy.agent_policy.v1"
    assert result.decision == AgentDecision.BLOCK
    assert result.exit_code == 2
    assert result.exit_code_meaning == "blocked by policy or risk decision"
    assert result.recommended_next_action == "Block non-interactive package use until a human reviews the judgement evidence."
    assert result.evidence_summary["evidence_count"] >= len(result.evidence)
    assert result.policy == {
        "schema_version": "pkgwhy.agent_policy.v1",
        "decision_source": "agent_policy",
        "non_interactive": True,
    }
    assert result.policy_decision_source == "agent_policy"
    assert any("unknown-risk" in reason for reason in result.reasons)
    assert any("Non-interactive package use" in reason for reason in result.reasons)


def test_interactive_unknown_package_requires_manual_review() -> None:
    result = evaluate_package_policy(
        _judgement(risk_level=RiskLevel.UNKNOWN, decision=AgentDecision.REVIEW_MANUALLY),
        non_interactive=False,
    )

    assert result.decision == AgentDecision.REVIEW_MANUALLY
    assert result.non_interactive is False
    assert any("unknown-risk" in reason for reason in result.reasons)


def test_non_interactive_low_risk_allow_remains_allowed() -> None:
    result = evaluate_package_policy(
        _judgement(risk_level=RiskLevel.LOW, decision=AgentDecision.ALLOW),
        non_interactive=True,
    )

    assert result.decision == AgentDecision.ALLOW
    assert result.policy_decision_source == "package_judgement"
    assert result.reasons == []
    assert result.recommendation == "Existing package recommendation."


def test_policy_can_require_evidence_for_agent_use() -> None:
    result = evaluate_package_policy(
        _judgement(risk_level=RiskLevel.LOW, decision=AgentDecision.ALLOW, evidence=[]),
        policy=AgentPolicyConfig(require_pkgwhy_judgement=True),
        non_interactive=False,
    )

    assert result.decision == AgentDecision.REVIEW_MANUALLY
    assert any("supporting evidence" in reason for reason in result.reasons)

import json

from pkgwhy.core.models import AgentDecision, Confidence, PackageJudgement, RiskLevel, SourceAvailability
from pkgwhy.policy.agent_policy import evaluate_package_policy
from pkgwhy.policy.audit_log import AGENT_DECISION_LOG_SCHEMA_VERSION, write_agent_package_decision_log


def test_write_agent_package_decision_log_omits_full_judgement_evidence(tmp_path) -> None:
    judgement = PackageJudgement(
        package="demo/package",
        version="1.0.0",
        decision=AgentDecision.REVIEW_MANUALLY,
        risk_level=RiskLevel.UNKNOWN,
        confidence=Confidence.LOW,
        summary="Synthetic package judgement.",
        source_availability=SourceAvailability.NOT_INSTALLED,
        installed_size_bytes=0,
        recommendation="Review manually.",
        evidence=["Sensitive-looking evidence should stay out of compact decision logs."],
    )
    result = evaluate_package_policy(judgement, non_interactive=True)

    log_path = write_agent_package_decision_log(result, log_root=tmp_path)

    data = json.loads(log_path.read_text(encoding="utf-8"))
    assert data["schema_version"] == AGENT_DECISION_LOG_SCHEMA_VERSION
    assert data["precheck_schema_version"] == "pkgwhy.agent_package_precheck.v1"
    assert data["policy_schema_version"] == "pkgwhy.agent_policy.v1"
    assert data["package"] == "demo/package"
    assert data["decision"] == "block"
    assert data["reason_count"] == len(result.reasons)
    assert "package_judgement" not in data
    assert "Sensitive-looking evidence" not in log_path.read_text(encoding="utf-8")


def test_write_agent_package_decision_log_fails_safely_when_log_root_is_unwritable(tmp_path) -> None:
    judgement = PackageJudgement(
        package="demo",
        version="1.0.0",
        decision=AgentDecision.REVIEW_MANUALLY,
        risk_level=RiskLevel.UNKNOWN,
        confidence=Confidence.LOW,
        summary="Synthetic package judgement.",
        source_availability=SourceAvailability.NOT_INSTALLED,
        installed_size_bytes=0,
        recommendation="Review manually.",
    )
    result = evaluate_package_policy(judgement, non_interactive=True)
    invalid_root = tmp_path / "not-a-directory"
    invalid_root.write_text("not a directory", encoding="utf-8")

    assert write_agent_package_decision_log(result, log_root=invalid_root) is None

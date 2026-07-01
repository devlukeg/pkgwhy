import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pkgwhy.cli import app
from pkgwhy.core.models import AgentDecision, HashStatus, RiskLevel, ToolTrustState
from pkgwhy.registry.local import init_local_registry, load_registry_index, save_registry_index
from pkgwhy.registry.publish import publish_local_tool
from pkgwhy.registry.tools import judge_tool
from pkgwhy.registry.trust import set_tool_trust_state

runner = CliRunner()


def test_judge_tool_reports_verified_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    init_local_registry(tmp_path / "registry")
    script = tmp_path / "hello_tool.py"
    script.write_text("print('hello')\n", encoding="utf-8")
    publish_local_tool(script)

    judgement = judge_tool("local/hello_tool")

    assert judgement.schema_version == "pkgwhy.tool_judgement.v1"
    assert judgement.command == "pkgwhy tool judge"
    assert judgement.target == "local/hello_tool"
    assert judgement.target_type == "tool"
    assert judgement.hash_status == HashStatus.VERIFIED
    assert judgement.signature_status == "not_implemented"
    assert judgement.trust_state == ToolTrustState.UNKNOWN
    assert judgement.decision == AgentDecision.REVIEW_MANUALLY
    assert judgement.exit_code == 1
    assert judgement.exit_code_meaning == "review or caution required before proceeding"
    assert judgement.recommended_next_action
    assert judgement.evidence_summary["evidence_count"] >= len(judgement.evidence)
    assert judgement.source_freshness == "local_registry_snapshot"
    assert judgement.manifest.name == "hello_tool"


def test_registry_trust_state_updates_tool_judgement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    init_local_registry(tmp_path / "registry")
    script = tmp_path / "trusted_tool.py"
    script.write_text("print('trusted')\n", encoding="utf-8")
    publish_local_tool(script)

    entry = set_tool_trust_state("local/trusted_tool", ToolTrustState.TRUSTED)
    judgement = judge_tool("local/trusted_tool")

    assert entry.trust_state == ToolTrustState.TRUSTED
    assert judgement.trust_state == ToolTrustState.TRUSTED
    assert judgement.decision == AgentDecision.REVIEW_MANUALLY


@pytest.mark.parametrize(
    ("state", "expected_decision", "expected_risk"),
    [
        (ToolTrustState.TRUSTED, AgentDecision.REVIEW_MANUALLY, RiskLevel.MEDIUM),
        (ToolTrustState.REVIEWED, AgentDecision.REVIEW_MANUALLY, RiskLevel.MEDIUM),
        (ToolTrustState.UNKNOWN, AgentDecision.REVIEW_MANUALLY, RiskLevel.MEDIUM),
        (ToolTrustState.QUARANTINED, AgentDecision.BLOCK, RiskLevel.HIGH),
        (ToolTrustState.BLOCKED, AgentDecision.BLOCK, RiskLevel.CRITICAL),
    ],
)
def test_tool_judgement_applies_registry_trust_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: ToolTrustState,
    expected_decision: AgentDecision,
    expected_risk: RiskLevel,
) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    init_local_registry(tmp_path / "registry")
    script = tmp_path / f"{state.value}_tool.py"
    script.write_text("print('trust state')\n", encoding="utf-8")
    publish_local_tool(script)
    if state != ToolTrustState.UNKNOWN:
        set_tool_trust_state(f"local/{state.value}_tool", state)

    judgement = judge_tool(f"local/{state.value}_tool")

    assert judgement.trust_state == state
    assert judgement.decision == expected_decision
    assert judgement.risk_level == expected_risk
    assert judgement.exit_code == (2 if expected_decision == AgentDecision.BLOCK else 1)
    assert f"Registry trust state is {state.value}." in judgement.evidence
    if state in {ToolTrustState.QUARANTINED, ToolTrustState.BLOCKED}:
        assert "registry trust state" in judgement.reason.lower()
        assert any("trust state" in warning.lower() for warning in judgement.warnings)


def test_judge_tool_blocks_hash_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    registry_path = tmp_path / "registry"
    init_local_registry(registry_path)
    script = tmp_path / "hello_tool.py"
    script.write_text("print('hello')\n", encoding="utf-8")
    publish_local_tool(script)
    index = load_registry_index(registry_path)
    index.tools[0].sha256 = "0" * 64
    save_registry_index(registry_path, index)

    judgement = judge_tool("hello_tool")

    assert judgement.hash_status == HashStatus.MISMATCH
    assert judgement.decision == AgentDecision.BLOCK


def test_judge_tool_reports_missing_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    registry_path = tmp_path / "registry"
    init_local_registry(registry_path)
    script = tmp_path / "missing_bundle.py"
    script.write_text("print('missing')\n", encoding="utf-8")
    publish_local_tool(script)
    index = load_registry_index(registry_path)
    (registry_path / index.tools[0].bundle_path).unlink()

    judgement = judge_tool("local/missing_bundle")

    assert judgement.hash_status == HashStatus.MISSING
    assert judgement.decision == AgentDecision.REVIEW_MANUALLY
    assert judgement.risk_level == RiskLevel.UNKNOWN
    assert "missing" in judgement.reason


def test_judge_tool_rejects_corrupt_registry_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    registry_path = tmp_path / "registry"
    init_local_registry(registry_path)
    (registry_path / "pkgwhy-registry.json").write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="Could not read registry index"):
        judge_tool("local/anything")


def test_judge_tool_rejects_registry_entry_path_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    registry_path = tmp_path / "registry"
    init_local_registry(registry_path)
    script = tmp_path / "path_escape.py"
    script.write_text("print('escape')\n", encoding="utf-8")
    publish_local_tool(script)
    index = load_registry_index(registry_path)
    index.tools[0].manifest_path = "../manifest.json"
    save_registry_index(registry_path, index)

    with pytest.raises(ValueError, match="escapes registry root"):
        judge_tool("local/path_escape")


def test_tool_cli_inspect_and_judge_json(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    registry_path = tmp_path / "registry"
    script = tmp_path / "hello_tool.py"
    script.write_text("print('hello')\n", encoding="utf-8")

    assert runner.invoke(app, ["registry", "init", str(registry_path)], env=env).exit_code == 0
    assert runner.invoke(app, ["publish", str(script)], env=env).exit_code == 0
    inspect_result = runner.invoke(app, ["tool", "inspect", "local/hello_tool"], env=env)
    judge_result = runner.invoke(app, ["tool", "judge", "local/hello_tool", "--json"], env=env)

    assert inspect_result.exit_code == 0
    assert "Hash status: verified" in inspect_result.output
    assert "Trust state: unknown" in inspect_result.output
    assert "Signature status: not_implemented" in inspect_result.output
    assert judge_result.exit_code == 0
    data = json.loads(judge_result.output)
    assert data["schema_version"] == "pkgwhy.tool_judgement.v1"
    assert data["command"] == "pkgwhy tool judge"
    assert data["target"] == "local/hello_tool"
    assert data["target_type"] == "tool"
    assert data["hash_status"] == "verified"
    assert data["trust_state"] == "unknown"
    assert data["signature_status"] == "not_implemented"
    assert data["exit_code_meaning"] == "review or caution required before proceeding"
    assert data["recommended_next_action"]
    assert data["evidence_summary"]["evidence_count"] >= len(data["evidence"])


def test_registry_trust_commands_mark_and_list_tools(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    registry_path = tmp_path / "registry"
    script = tmp_path / "blocked_tool.py"
    script.write_text("print('blocked')\n", encoding="utf-8")

    assert runner.invoke(app, ["registry", "init", str(registry_path)], env=env).exit_code == 0
    assert runner.invoke(app, ["publish", str(script)], env=env).exit_code == 0
    trust_result = runner.invoke(app, ["registry", "trust", "local/blocked_tool"], env=env)
    review_result = runner.invoke(app, ["registry", "review", "local/blocked_tool"], env=env)
    quarantine_result = runner.invoke(app, ["registry", "quarantine", "local/blocked_tool"], env=env)
    block_result = runner.invoke(app, ["registry", "block", "local/blocked_tool"], env=env)
    blocked_result = runner.invoke(app, ["registry", "blocked"], env=env)

    assert trust_result.exit_code == 0
    assert "local/blocked_tool 0.1.0: trusted" in trust_result.output
    assert review_result.exit_code == 0
    assert "local/blocked_tool 0.1.0: reviewed" in review_result.output
    assert quarantine_result.exit_code == 0
    assert "local/blocked_tool 0.1.0: quarantined" in quarantine_result.output
    assert block_result.exit_code == 0
    assert "local/blocked_tool 0.1.0: blocked" in block_result.output
    assert blocked_result.exit_code == 0
    assert "blocked_tool" in blocked_result.output
    assert "blocked" in blocked_result.output.split("blocked_tool", 1)[1]


def test_registry_trust_commands_emit_json(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    registry_path = tmp_path / "registry"
    script = tmp_path / "json_tool.py"
    script.write_text("print('json')\n", encoding="utf-8")

    assert runner.invoke(app, ["registry", "init", str(registry_path)], env=env).exit_code == 0
    assert runner.invoke(app, ["publish", str(script)], env=env).exit_code == 0

    trust_result = runner.invoke(app, ["registry", "trust", "local/json_tool", "--json"], env=env)
    review_result = runner.invoke(app, ["registry", "review", "local/json_tool", "--json"], env=env)
    quarantine_result = runner.invoke(app, ["registry", "quarantine", "local/json_tool", "--json"], env=env)
    block_result = runner.invoke(app, ["registry", "block", "local/json_tool", "--json"], env=env)
    blocked_result = runner.invoke(app, ["registry", "blocked", "--json"], env=env)

    for result, command, trust_state in [
        (trust_result, "pkgwhy registry trust", "trusted"),
        (review_result, "pkgwhy registry review", "reviewed"),
        (quarantine_result, "pkgwhy registry quarantine", "quarantined"),
        (block_result, "pkgwhy registry block", "blocked"),
    ]:
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["schema_version"] == "pkgwhy.registry_trust_state.v1"
        assert data["command"] == command
        assert data["target"] == "local/json_tool"
        assert data["target_type"] == "tool"
        assert data["trust_state"] == trust_state
        assert data["exit_code"] == 0
        assert data["exit_code_meaning"] == "allowed or completed successfully"
        assert data["evidence"]

    assert blocked_result.exit_code == 0
    blocked_data = json.loads(blocked_result.output)
    assert blocked_data["schema_version"] == "pkgwhy.registry_blocked.v1"
    assert blocked_data["command"] == "pkgwhy registry blocked"
    assert blocked_data["blocked_count"] == 1
    assert blocked_data["tools"][0]["target"] == "local/json_tool"
    assert blocked_data["tools"][0]["trust_state"] == "blocked"


def test_registry_blocked_json_reports_configuration_errors(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}

    result = runner.invoke(app, ["registry", "blocked", "--json"], env=env)

    assert result.exit_code == 3
    data = json.loads(result.output)
    assert data["schema_version"] == "pkgwhy.error.v1"
    assert data["command"] == "pkgwhy registry blocked"
    assert data["target_type"] == "registry_trust_state"
    assert data["error_type"] == "registry_configuration_error"
    assert data["exit_code_meaning"] == "tool, configuration, or user input error"


def test_tool_judge_json_reports_lookup_errors(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}

    result = runner.invoke(app, ["tool", "judge", "local/missing_tool", "--json"], env=env)

    assert result.exit_code == 3
    data = json.loads(result.output)
    assert data["schema_version"] == "pkgwhy.error.v1"
    assert data["command"] == "pkgwhy tool judge"
    assert data["target"] == "local/missing_tool"
    assert data["target_type"] == "tool"
    assert data["error_type"] == "tool_lookup_error"
    assert data["exit_code_meaning"] == "tool, configuration, or user input error"

from pathlib import Path

import pytest

from pkgwhy.core.models import AgentDecision, HashStatus
from pkgwhy.policy.tool_execution import evaluate_tool_execution_policy
from pkgwhy.registry.local import init_local_registry, load_registry_index, save_registry_index
from pkgwhy.registry.publish import publish_local_tool
from pkgwhy.registry.run import run_local_tool
from pkgwhy.registry.tools import judge_tool


def test_policy_blocks_hash_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    registry_path = tmp_path / "registry"
    init_local_registry(registry_path)
    script = tmp_path / "policy_hash.py"
    script.write_text("print('hash')\n", encoding="utf-8")
    publish_local_tool(script)
    index = load_registry_index(registry_path)
    index.tools[0].sha256 = "0" * 64
    save_registry_index(registry_path, index)

    judgement = judge_tool("local/policy_hash")
    result = evaluate_tool_execution_policy(judgement)

    assert judgement.hash_status == HashStatus.MISMATCH
    assert result.allowed is False
    assert result.decision == AgentDecision.BLOCK
    assert "hash is not verified" in " ".join(result.reasons)


def test_policy_blocks_default_script_for_non_interactive_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    init_local_registry(tmp_path / "registry")
    script = tmp_path / "policy_agent.py"
    script.write_text("print('agent')\n", encoding="utf-8")
    publish_local_tool(script)

    judgement = judge_tool("local/policy_agent")
    result = evaluate_tool_execution_policy(judgement, non_interactive=True)

    assert result.allowed is False
    assert result.decision == AgentDecision.BLOCK
    assert "Non-interactive execution is not allowed" in " ".join(result.reasons)


def test_runner_blocks_non_interactive_default_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    init_local_registry(tmp_path / "registry")
    script = tmp_path / "noninteractive_runner.py"
    script.write_text("print('should not run')\n", encoding="utf-8")
    publish_local_tool(script)

    with pytest.raises(ValueError, match="Tool policy blocks execution"):
        run_local_tool("local/noninteractive_runner", non_interactive=True)


def test_policy_warns_for_unsigned_interactive_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    init_local_registry(tmp_path / "registry")
    script = tmp_path / "unsigned_policy.py"
    script.write_text("print('unsigned')\n", encoding="utf-8")
    publish_local_tool(script)

    judgement = judge_tool("local/unsigned_policy")
    result = evaluate_tool_execution_policy(judgement)

    assert result.allowed is True
    assert result.decision == AgentDecision.REVIEW_MANUALLY
    assert any("not implemented" in warning for warning in result.warnings)

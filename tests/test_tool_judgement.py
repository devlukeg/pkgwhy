import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pkgwhy.cli import app
from pkgwhy.core.models import AgentDecision, HashStatus
from pkgwhy.registry.local import init_local_registry, load_registry_index, save_registry_index
from pkgwhy.registry.publish import publish_local_tool
from pkgwhy.registry.tools import judge_tool

runner = CliRunner()


def test_judge_tool_reports_verified_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    init_local_registry(tmp_path / "registry")
    script = tmp_path / "hello_tool.py"
    script.write_text("print('hello')\n", encoding="utf-8")
    publish_local_tool(script)

    judgement = judge_tool("local/hello_tool")

    assert judgement.schema_version == "pkgwhy.tool_judgement.v1"
    assert judgement.hash_status == HashStatus.VERIFIED
    assert judgement.signature_status == "not_implemented"
    assert judgement.decision == AgentDecision.REVIEW_MANUALLY
    assert judgement.manifest.name == "hello_tool"


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
    assert "Signature status: not_implemented" in inspect_result.output
    assert judge_result.exit_code == 0
    data = json.loads(judge_result.output)
    assert data["schema_version"] == "pkgwhy.tool_judgement.v1"
    assert data["hash_status"] == "verified"
    assert data["signature_status"] == "not_implemented"

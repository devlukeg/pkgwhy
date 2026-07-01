import json
from pathlib import Path

from typer.testing import CliRunner

from pkgwhy.core.models import AgentDecision, RiskLevel, ToolValidationIssue, ToolValidationResult
from pkgwhy.cli import app
from pkgwhy.registry.validate import validate_tool_source

runner = CliRunner()


def test_validate_tool_source_accepts_fixture_without_writing_registry() -> None:
    fixture = Path("tests/fixtures/private-tools/hello-tool")

    result = validate_tool_source(fixture)

    assert result.schema_version == "pkgwhy.tool_validation.v1"
    assert result.command == "pkgwhy tool validate"
    assert result.target == str(fixture)
    assert result.target_type == "tool_folder"
    assert result.valid is True
    assert result.decision == "allow"
    assert result.exit_code == 0
    assert result.manifest is not None
    assert result.manifest.name == "hello-tool"
    assert result.entrypoint == "hello.py"
    assert result.policy["executes_tool_code"] is False
    assert result.policy["writes_to_registry"] is False


def test_validate_tool_source_reports_missing_entrypoint(tmp_path: Path) -> None:
    tool_dir = tmp_path / "bad-tool"
    tool_dir.mkdir()
    (tool_dir / "pkgwhy.toml").write_text(
        """
[tool]
name = "bad-tool"
owner = "local"
version = "0.1.0"
description = "Missing entrypoint"
artifact_type = "folder"
entrypoint = "missing.py"
""",
        encoding="utf-8",
    )

    result = validate_tool_source(tool_dir)

    assert result.valid is False
    assert result.decision == "block"
    assert result.exit_code == 2
    assert any(issue.code == "entrypoint_missing" for issue in result.issues)


def test_validate_tool_source_reports_static_capabilities(tmp_path: Path) -> None:
    tool_dir = tmp_path / "cap-tool"
    tool_dir.mkdir()
    (tool_dir / "pkgwhy.toml").write_text(
        """
[tool]
name = "cap-tool"
owner = "local"
version = "0.1.0"
description = "Capability fixture"
artifact_type = "folder"
entrypoint = "main.py"
""",
        encoding="utf-8",
    )
    (tool_dir / "main.py").write_text(
        "import os\nimport subprocess\nprint(os.getenv('TOKEN'))\nsubprocess.run(['true'])\n",
        encoding="utf-8",
    )

    result = validate_tool_source(tool_dir)

    assert result.valid is True
    assert result.decision == "allow_with_caution"
    assert result.exit_code == 1
    assert "Environment variable access signals" in result.detected_capabilities
    assert "Subprocess or shell execution signals" in result.detected_capabilities
    assert any(issue.code == "declared_permissions_missing" for issue in result.issues)


def test_validate_tool_source_reports_underdeclared_permissions(tmp_path: Path) -> None:
    tool_dir = tmp_path / "underdeclared-tool"
    tool_dir.mkdir()
    (tool_dir / "pkgwhy.toml").write_text(
        """
[tool]
name = "underdeclared-tool"
owner = "local"
version = "0.1.0"
description = "Underdeclared permissions"
artifact_type = "folder"
entrypoint = "main.py"
declared_permissions = ["network"]
""",
        encoding="utf-8",
    )
    (tool_dir / "main.py").write_text("import subprocess\nsubprocess.run(['true'])\n", encoding="utf-8")

    result = validate_tool_source(tool_dir)

    assert result.valid is True
    assert result.decision == "allow_with_caution"
    missing = [issue for issue in result.issues if issue.code == "declared_permissions_missing"]
    assert missing
    assert "subprocess" in missing[0].message


def test_validate_tool_source_prunes_excluded_directories(tmp_path: Path) -> None:
    tool_dir = tmp_path / "excluded-tool"
    nested = tool_dir / ".venv" / "lib"
    nested.mkdir(parents=True)
    (tool_dir / "pkgwhy.toml").write_text(
        """
[tool]
name = "excluded-tool"
owner = "local"
version = "0.1.0"
description = "Excluded path fixture"
artifact_type = "folder"
entrypoint = "main.py"
""",
        encoding="utf-8",
    )
    (tool_dir / "main.py").write_text("print('ok')\n", encoding="utf-8")
    (nested / "ignored.py").write_text("import subprocess\nsubprocess.run(['true'])\n", encoding="utf-8")

    result = validate_tool_source(tool_dir)

    skipped = [issue for issue in result.issues if issue.code == "unsupported_path_skipped"]
    assert len(skipped) == 1
    assert skipped[0].path == ".venv"
    assert "Subprocess or shell execution signals" not in result.detected_capabilities


def test_tool_validate_cli_json() -> None:
    result = runner.invoke(app, ["tool", "validate", "tests/fixtures/private-tools/hello-tool", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == "pkgwhy.tool_validation.v1"
    assert data["command"] == "pkgwhy tool validate"
    assert data["target"] == "tests/fixtures/private-tools/hello-tool"
    assert data["target_type"] == "tool_folder"
    assert data["valid"] is True
    assert data["exit_code_meaning"] == "allowed or completed successfully"
    assert data["policy"]["executes_tool_code"] is False
    assert data["policy"]["writes_to_registry"] is False


def test_tool_validation_result_normalizes_error_issue_consistency() -> None:
    result = ToolValidationResult(
        target="bad-tool",
        target_type="tool_folder",
        valid=True,
        decision=AgentDecision.ALLOW,
        risk_level=RiskLevel.LOW,
        issues=[
            ToolValidationIssue(
                code="entrypoint_missing",
                severity="error",
                message="Tool entrypoint does not exist.",
            )
        ],
    )

    assert result.valid is False
    assert result.decision == AgentDecision.BLOCK
    assert result.risk_level == RiskLevel.HIGH
    assert result.exit_code == 2
    assert result.errors == ["Tool entrypoint does not exist."]


def test_tool_validation_result_invalid_state_cannot_keep_success_exit_code() -> None:
    result = ToolValidationResult(
        target="bad-tool",
        target_type="tool_folder",
        valid=False,
        decision=AgentDecision.ALLOW,
        risk_level=RiskLevel.LOW,
        exit_code=0,
    )

    assert result.valid is False
    assert result.decision == AgentDecision.BLOCK
    assert result.exit_code == 2
    assert result.exit_code_meaning == "blocked by policy or risk decision"

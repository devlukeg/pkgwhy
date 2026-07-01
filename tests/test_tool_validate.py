import json
from pathlib import Path

from typer.testing import CliRunner

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

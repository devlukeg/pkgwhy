import json
from pathlib import Path

from typer.testing import CliRunner

from pkgwhy.cli import app

runner = CliRunner()


def _json_result(args: list[str]):
    result = runner.invoke(app, args)
    assert result.output
    return result, json.loads(result.output)


def test_agent_check_dispatches_package_target() -> None:
    result, data = _json_result(["agent", "check", "typer", "--json"])

    assert result.exit_code in {0, 1, 2, 4}
    assert data["schema_version"] == "pkgwhy.agent_check.v1"
    assert data["command"] == "pkgwhy agent check"
    assert data["target"] == "typer"
    assert data["target_type"] == "package"
    assert data["result_schema_version"] == "pkgwhy.precheck.v1"
    assert data["result"]["package"] == "typer"
    assert data["exit_code_meaning"]


def test_agent_check_dispatches_requirements_file() -> None:
    target = "tests/fixtures/precheck/requirements.txt"
    result, data = _json_result(["agent", "check", target, "--json"])

    assert result.exit_code in {0, 1, 2, 4}
    assert data["schema_version"] == "pkgwhy.agent_check.v1"
    assert data["target_type"] == "requirements"
    assert data["result_schema_version"] == "pkgwhy.precheck_batch.v1"
    assert data["result"]["source"] == target
    assert "blocking_targets" in data["result"]


def test_agent_check_dispatches_pyproject_file(tmp_path: Path) -> None:
    pyproject = tmp_path / "renamed.toml"
    pyproject.write_text(
        """
[project]
name = "agent-check-fixture"
dependencies = ["typer"]
""",
        encoding="utf-8",
    )

    result, data = _json_result(["agent", "check", str(pyproject), "--json"])

    assert result.exit_code in {0, 1, 2, 4}
    assert data["schema_version"] == "pkgwhy.agent_check.v1"
    assert data["target_type"] == "pyproject"
    assert data["result_schema_version"] == "pkgwhy.precheck_batch.v1"
    assert data["result"]["source"] == str(pyproject)


def test_agent_check_dispatches_local_tool_folder() -> None:
    target = "tests/fixtures/private-tools/hello-tool"
    result, data = _json_result(["agent", "check", target, "--json"])

    assert result.exit_code == 0
    assert data["schema_version"] == "pkgwhy.agent_check.v1"
    assert data["target_type"] == "tool"
    assert data["decision"] == "allow"
    assert data["result_schema_version"] == "pkgwhy.tool_validation.v1"
    assert data["result"]["policy"]["executes_tool_code"] is False


def test_agent_check_dispatches_malformed_local_directory_to_tool_validation(tmp_path: Path) -> None:
    tool_dir = tmp_path / "missing-manifest-tool"
    tool_dir.mkdir()

    result, data = _json_result(["agent", "check", str(tool_dir), "--json"])

    assert result.exit_code == 2
    assert data["schema_version"] == "pkgwhy.agent_check.v1"
    assert data["target_type"] == "tool"
    assert data["decision"] == "block"
    assert data["result_schema_version"] == "pkgwhy.tool_validation.v1"
    assert data["result"]["valid"] is False
    assert data["result"]["issues"][0]["code"] == "manifest_invalid"

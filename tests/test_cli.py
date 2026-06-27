import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from pkgwhy.cli import app
from pkgwhy.core.models import AgentDecision, PackageJudgement, RiskLevel
from pkgwhy.metadata.installed import get_installed_package


runner = CliRunner()


def _command_option_names(*path: str) -> set[str]:
    command = typer.main.get_command(app)
    for name in path:
        command = command.commands[name]
    return {
        option
        for parameter in command.params
        for option in getattr(parameter, "opts", ())
    }


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Explain, inspect, judge packages, and run local private tools" in result.output
    assert "dynamic" in result.output
    assert "agent" in result.output


def test_agent_help_surfaces_policy_commands() -> None:
    result = runner.invoke(app, ["agent", "--help"])

    assert result.exit_code == 0
    assert "Agent-facing policy and package precheck commands" in result.output
    assert "policy" in result.output
    assert "precheck" in result.output


def test_agent_policy_json_is_schema_versioned_and_conservative() -> None:
    result = runner.invoke(app, ["agent", "policy", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == "pkgwhy.agent_policy.v1"
    assert data["allow_public_pypi"] is False
    assert data["allow_unpinned_dependencies"] is False
    assert data["allow_unsigned_tools"] is False
    assert data["non_interactive_default_decision"] == "block"


def test_agent_precheck_missing_package_blocks_non_interactive_json(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    package_name = "definitely-not-installed-pkgwhy-agent-precheck-4c7f6"
    assert get_installed_package(package_name) is None

    result = runner.invoke(app, ["agent", "precheck", package_name, "--json"], env=env)

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == "pkgwhy.agent_package_precheck.v1"
    assert data["policy_schema_version"] == "pkgwhy.agent_policy.v1"
    assert data["target_type"] == "package"
    assert data["package"] == package_name
    assert data["risk_level"] == "unknown"
    assert data["decision"] == "block"
    assert data["non_interactive"] is True
    assert data["policy_decision_source"] == "agent_policy"
    assert data["package_judgement"]["schema_version"] == "pkgwhy.package_judgement.v1"
    log_files = list((tmp_path / "config" / "agent-decisions").rglob("*.json"))
    assert len(log_files) == 1


def test_agent_judge_interactive_missing_package_requires_review_json(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    package_name = "definitely-not-installed-pkgwhy-agent-judge-a0186"
    assert get_installed_package(package_name) is None

    result = runner.invoke(app, ["agent", "judge", package_name, "--interactive", "--json"], env=env)

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == "pkgwhy.agent_package_precheck.v1"
    assert data["decision"] == "review_manually"
    assert data["non_interactive"] is False
    log_files = list((tmp_path / "config" / "agent-decisions").rglob("*.json"))
    assert len(log_files) == 1


def test_dynamic_help_surfaces_experimental_command() -> None:
    result = runner.invoke(app, ["dynamic", "--help"])

    assert result.exit_code == 0
    assert "Experimental dynamic sandbox analysis" in result.output


def test_dynamic_inspect_help_surfaces_safe_options() -> None:
    result = runner.invoke(app, ["dynamic", "inspect", "--help"])

    assert result.exit_code == 0
    option_names = _command_option_names("dynamic", "inspect")
    assert "--container" in option_names
    assert "--network" in option_names
    assert "--json" in option_names


def test_dynamic_inspect_fails_safely_without_backend(monkeypatch) -> None:
    monkeypatch.setattr("pkgwhy.dynamic.analysis.shutil.which", lambda _: None)

    result = runner.invoke(app, ["dynamic", "inspect", "demo-target", "--container"])
    normalized_output = " ".join(result.output.split())

    assert result.exit_code == 1
    assert "not a production sandbox" in normalized_output
    assert "out of scope for 1.0 production security guarantees" in normalized_output
    assert "Refusing to run dynamic analysis" in normalized_output
    assert "Docker container backend is unavailable" in normalized_output
    assert "Target was not executed: demo-target" in normalized_output


def test_dynamic_inspect_rejects_network_enabled_mode() -> None:
    result = runner.invoke(app, ["dynamic", "inspect", "demo-target", "--container", "--network", "on"])

    assert result.exit_code == 1
    assert "Only network mode 'off' is accepted" in result.output


def test_dynamic_inspect_json_uses_schema_and_empty_events(monkeypatch) -> None:
    monkeypatch.setattr("pkgwhy.dynamic.analysis.shutil.which", lambda _: None)

    result = runner.invoke(app, ["dynamic", "inspect", "demo-target", "--container", "--json"])

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["schema_version"] == "pkgwhy.dynamic_analysis.v1"
    assert data["target"] == "demo-target"
    assert data["mode"] == "inspect"
    assert data["sandbox_backend"] == "container"
    assert data["network_mode"] == "off"
    assert data["filesystem_mode"] == "scratch"
    assert data["status"] == "backend_unavailable"
    assert data["decision"] == "block"
    assert data["process_events"] == []
    assert data["filesystem_events"] == []
    assert data["network_events"] == []
    assert any("out of scope for 1.0 production security guarantees" in warning for warning in data["warnings"])
    assert any("No dynamic sandbox backend" in limitation for limitation in data["limitations"])


def test_judge_json_for_missing_package_is_stable() -> None:
    package_name = "definitely-not-installed-pkgwhy-test-package-7f7b1c90"
    assert get_installed_package(package_name) is None
    result = runner.invoke(app, ["judge", package_name, "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    PackageJudgement.model_validate(data)
    assert data["schema_version"] == "pkgwhy.package_judgement.v1"
    assert data["risk_model_version"] == "pkgwhy.risk_model.v1"
    assert data["package"] == package_name
    assert data["risk_level"] == "unknown"
    assert data["decision"] == "review_manually"
    assert data["confidence"] == "low"
    assert isinstance(data["warnings"], list)
    assert len(data["warnings"]) > 0
    assert any("not installed" in warning.lower() for warning in data["warnings"])


def test_judge_json_contains_agent_contract_fields_for_installed_package() -> None:
    assert get_installed_package("typer") is not None
    result = runner.invoke(app, ["judge", "typer", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    PackageJudgement.model_validate(data)
    assert data["schema_version"] == "pkgwhy.package_judgement.v1"
    assert data["risk_model_version"] == "pkgwhy.risk_model.v1"
    assert data["package"] == "typer"
    assert data["decision"] in {decision.value for decision in AgentDecision}
    assert data["risk_level"] in {risk.value for risk in RiskLevel}
    assert isinstance(data["installed_size_bytes"], int)
    assert isinstance(data["detected_capabilities"], list)
    assert isinstance(data["warnings"], list)
    assert isinstance(data["evidence"], list)
    assert isinstance(data["risk_rules"], list)
    assert data["risk_rules"]
    assert all("category" in rule for rule in data["risk_rules"])
    assert all("false_positive_note" in rule for rule in data["risk_rules"])
    assert isinstance(data["known_vulnerabilities"], list)
    assert data["provenance"] is not None
    assert data["provenance"]["attestation_status"] == "not_implemented"
    assert "not proof" in data["capability_exposure_note"].lower()


@pytest.mark.parametrize("limit", ["0", "-1"])
def test_scan_rejects_invalid_limit(limit: str) -> None:
    result = runner.invoke(app, ["scan", "--limit", limit])

    assert result.exit_code != 0
    assert "limit must be greater than zero" in result.output


def test_why_command_reports_declared_and_lockfile_evidence(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
dependencies = ["Typer>=0.12"]
""",
        encoding="utf-8",
    )
    (tmp_path / "poetry.lock").write_text(
        """
[[package]]
name = "typer"
version = "0.1.0"
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["why", "typer", "--project-root", str(tmp_path)])

    assert result.exit_code == 0
    assert "Dependency status: direct" in result.output
    assert "Declared in: pyproject.toml" in result.output
    assert "Lockfile signal: poetry.lock" in result.output


def test_registry_commands_manage_local_config(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    registry_path = tmp_path / "registry"

    init_result = runner.invoke(app, ["registry", "init", str(registry_path)], env=env)
    list_result = runner.invoke(app, ["registry", "list"], env=env)
    use_result = runner.invoke(app, ["registry", "use", "local"], env=env)

    assert init_result.exit_code == 0
    assert "Initialized registry 'local'" in init_result.output
    assert (registry_path / "pkgwhy-registry.json").exists()
    assert list_result.exit_code == 0
    assert "local" in list_result.output
    assert "present" in list_result.output
    assert use_result.exit_code == 0
    assert "Current registry: local" in use_result.output


def test_publish_command_publishes_script_to_current_registry(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    registry_path = tmp_path / "registry"
    script = tmp_path / "hello_tool.py"
    script.write_text("print('hello')\n", encoding="utf-8")

    init_result = runner.invoke(app, ["registry", "init", str(registry_path)], env=env)
    publish_result = runner.invoke(app, ["publish", str(script)], env=env)

    assert init_result.exit_code == 0
    assert publish_result.exit_code == 0
    assert "Published local/hello_tool 0.1.0" in publish_result.output
    assert "Signature status: not_implemented" in publish_result.output

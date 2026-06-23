import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pkgwhy.cli import app
from pkgwhy.core.models import AgentDecision, PackageJudgement, RiskLevel
from pkgwhy.metadata.installed import get_installed_package


runner = CliRunner()


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Explain, inspect, and judge Python packages" in result.output


def test_judge_json_for_missing_package_is_stable() -> None:
    package_name = "definitely-not-installed-pkgwhy-test-package-7f7b1c90"
    assert get_installed_package(package_name) is None
    result = runner.invoke(app, ["judge", package_name, "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    PackageJudgement.model_validate(data)
    assert data["schema_version"] == "pkgwhy.package_judgement.v1"
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
    assert data["package"] == "typer"
    assert data["decision"] in {decision.value for decision in AgentDecision}
    assert data["risk_level"] in {risk.value for risk in RiskLevel}
    assert isinstance(data["installed_size_bytes"], int)
    assert isinstance(data["detected_capabilities"], list)
    assert isinstance(data["warnings"], list)
    assert isinstance(data["evidence"], list)
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

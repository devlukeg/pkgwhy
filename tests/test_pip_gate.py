import json
from pathlib import Path

from typer.testing import CliRunner

from pkgwhy.cli import app
from pkgwhy.core.models import (
    AgentDecision,
    Confidence,
    PackageJudgement,
    PipInstallGateResult,
    PrecheckBatchResult,
    PrecheckSignalSummary,
    PreInstallPackagePrecheckResult,
    ReadabilityStatus,
    RiskLevel,
    SourceAvailability,
)
from pkgwhy.pip_gate import PipCommandResult, run_pip_install_gate

runner = CliRunner()


def _package_judgement(
    *,
    package: str = "demo-package",
    decision: AgentDecision = AgentDecision.ALLOW,
    risk_level: RiskLevel = RiskLevel.LOW,
    confidence: Confidence = Confidence.HIGH,
    warnings: list[str] | None = None,
) -> PackageJudgement:
    return PackageJudgement(
        package=package,
        version="1.0.0",
        decision=decision,
        risk_level=risk_level,
        confidence=confidence,
        summary="Controlled test package.",
        source_availability=SourceAvailability.INSTALLED_SOURCE_PRESENT,
        installed_size_bytes=10,
        detected_capabilities=[],
        warnings=warnings or [],
        recommendation="Controlled test recommendation.",
        evidence=["Controlled test evidence."],
    )


def _precheck(
    *,
    package: str = "demo-package",
    decision: AgentDecision = AgentDecision.ALLOW,
    risk_level: RiskLevel = RiskLevel.LOW,
    confidence: Confidence = Confidence.HIGH,
    exit_code: int = 0,
    warnings: list[str] | None = None,
) -> PreInstallPackagePrecheckResult:
    judgement = _package_judgement(
        package=package,
        decision=decision,
        risk_level=risk_level,
        confidence=confidence,
        warnings=warnings,
    )
    summary = PrecheckSignalSummary(status="not_requested")
    return PreInstallPackagePrecheckResult(
        requested=package,
        package=package,
        normalized_package=package,
        requested_specifier=None,
        requested_version=None,
        version="1.0.0",
        metadata_source="test_fixture",
        lookup_status="metadata_found",
        network_requested=False,
        artifacts_downloaded=False,
        decision=decision,
        exit_code=exit_code,
        risk_level=risk_level,
        confidence=confidence,
        policy_decision=decision,
        policy_reasons=[],
        summary="Controlled test package.",
        recommendation="Controlled test recommendation.",
        warnings=warnings or [],
        evidence=["Did not install, import, or execute inspected package code."],
        vulnerability_summary=summary,
        provenance_summary=summary,
        typosquat_summary=summary,
        static_summary=PrecheckSignalSummary(status="no_static_signals"),
        package_judgement=judgement,
    )


def _batch_precheck(result: PreInstallPackagePrecheckResult) -> PrecheckBatchResult:
    return PrecheckBatchResult(
        target_type="requirements",
        source="requirements.txt",
        package_count=1,
        decision=result.decision,
        exit_code=result.exit_code,
        risk_level=result.risk_level,
        confidence=result.confidence,
        warnings=list(result.warnings),
        results=[result],
    )


def test_pip_gate_invokes_fake_pip_only_after_allow(monkeypatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr("pkgwhy.pip_gate.build_package_precheck", lambda *args, **kwargs: _precheck())

    def fake_runner(command: list[str]) -> PipCommandResult:
        calls.append(command)
        return PipCommandResult(returncode=0)

    result = run_pip_install_gate(packages=["demo-package"], pip_runner=fake_runner, log_root=tmp_path)

    PipInstallGateResult.model_validate(result.model_dump(mode="json"))
    assert result.exit_code == 0
    assert result.pip_invoked is True
    assert result.pip_command[-2:] == ["install", "demo-package"]
    assert calls == [result.pip_command]
    assert result.log_path is not None
    log_data = json.loads(Path(result.log_path).read_text(encoding="utf-8"))
    assert log_data["schema_version"] == "pkgwhy.pip_install_decision_log.v1"
    assert log_data["pip_invoked"] is True
    assert "Controlled test evidence" not in Path(result.log_path).read_text(encoding="utf-8")


def test_pip_gate_blocks_without_invoking_pip(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "pkgwhy.pip_gate.build_package_precheck",
        lambda *args, **kwargs: _precheck(
            decision=AgentDecision.BLOCK,
            risk_level=RiskLevel.HIGH,
            confidence=Confidence.MEDIUM,
            exit_code=2,
        ),
    )

    result = run_pip_install_gate(
        packages=["demo-package"],
        pip_runner=lambda command: PipCommandResult(returncode=0),
        log_root=tmp_path,
    )

    assert result.exit_code == 2
    assert result.pip_invoked is False
    assert result.pip_command == []
    assert any("Policy blocks pip install" in reason for reason in result.reasons)


def test_pip_gate_review_override_is_explicit_and_logged(monkeypatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        "pkgwhy.pip_gate.build_package_precheck",
        lambda *args, **kwargs: _precheck(
            decision=AgentDecision.REVIEW_MANUALLY,
            risk_level=RiskLevel.MEDIUM,
            confidence=Confidence.MEDIUM,
            exit_code=1,
        ),
    )

    result = run_pip_install_gate(
        packages=["demo-package"],
        override_review=True,
        override_reason="controlled fixture approval",
        pip_runner=lambda command: calls.append(command) or PipCommandResult(returncode=0),
        log_root=tmp_path,
    )

    assert result.exit_code == 0
    assert result.override_used is True
    assert result.override_reason == "controlled fixture approval"
    assert result.pip_invoked is True
    assert calls == [result.pip_command]
    assert result.log_path is not None
    log_data = json.loads(Path(result.log_path).read_text(encoding="utf-8"))
    assert log_data["override_used"] is True
    assert log_data["override_reason"] == "controlled fixture approval"


def test_pip_gate_unavailable_precheck_does_not_allow_override(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "pkgwhy.pip_gate.build_package_precheck",
        lambda *args, **kwargs: _precheck(
            decision=AgentDecision.ALLOW_WITH_CAUTION,
            risk_level=RiskLevel.MEDIUM,
            confidence=Confidence.MEDIUM,
            exit_code=4,
            warnings=["Artifact coverage was partial."],
        ),
    )

    result = run_pip_install_gate(
        packages=["demo-package"],
        override_review=True,
        pip_runner=lambda command: PipCommandResult(returncode=0),
        log_root=tmp_path,
    )

    assert result.exit_code == 4
    assert result.override_used is False
    assert result.pip_invoked is False
    assert any("unavailable or incomplete" in reason for reason in result.reasons)


def test_pip_gate_requirements_file_uses_fake_pip_runner(monkeypatch, tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo-package==1.0.0\n", encoding="utf-8")
    monkeypatch.setattr("pkgwhy.pip_gate.build_requirements_precheck", lambda *args, **kwargs: _batch_precheck(_precheck()))
    calls: list[list[str]] = []

    result = run_pip_install_gate(
        requirement_file=requirements,
        pip_runner=lambda command: calls.append(command) or PipCommandResult(returncode=0),
        log_root=tmp_path / "logs",
    )

    assert result.target_type == "requirements"
    assert result.exit_code == 0
    assert result.pip_invoked is True
    assert result.pip_command[-3:] == ["install", "-r", str(requirements)]
    assert calls == [result.pip_command]


def test_pip_gate_strict_policy_requires_clean_allow(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "pkgwhy.pip_gate.build_package_precheck",
        lambda *args, **kwargs: _precheck(warnings=["Review warning."], exit_code=0),
    )

    result = run_pip_install_gate(
        packages=["demo-package"],
        policy="strict",
        pip_runner=lambda command: PipCommandResult(returncode=0),
        log_root=tmp_path,
    )

    assert result.exit_code == 1
    assert result.pip_invoked is False
    assert any("Strict policy" in reason for reason in result.reasons)


def test_pip_gate_cli_help_surfaces_install_command() -> None:
    result = runner.invoke(app, ["pip", "install", "--help"])

    assert result.exit_code == 0
    option_names = {
        option
        for parameter in __import__("typer").main.get_command(app).commands["pip"].commands["install"].params
        for option in getattr(parameter, "opts", ())
    }
    assert "--policy" in option_names
    assert "-r" in option_names
    assert "--override-review" in option_names
    assert "--override-block" in option_names
    assert "--dry-run" in option_names


def test_pip_gate_cli_json_dry_run_uses_precheck_and_never_pip(monkeypatch, tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    monkeypatch.setattr("pkgwhy.pip_gate.build_package_precheck", lambda *args, **kwargs: _precheck())
    monkeypatch.setattr(
        "pkgwhy.pip_gate._run_pip_command",
        lambda command: (_ for _ in ()).throw(AssertionError("pip should not be invoked in dry-run")),
    )

    result = runner.invoke(app, ["pip", "install", "demo-package", "--dry-run", "--json"], env=env)

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == "pkgwhy.pip_install_gate.v1"
    assert data["dry_run"] is True
    assert data["pip_invoked"] is False
    assert data["exit_code"] == 0
    assert list((tmp_path / "config" / "pip-install-decisions").rglob("*.json"))

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable, Literal

from pkgwhy.core.models import (
    AgentDecision,
    Confidence,
    PipInstallGateResult,
    PrecheckBatchResult,
    PreInstallPackagePrecheckResult,
    RiskLevel,
)
from pkgwhy.precheck import (
    PrecheckFileError,
    PrecheckTargetError,
    build_package_precheck,
    build_requirements_precheck,
)
from pkgwhy.registry.local import config_dir

PIP_INSTALL_DECISION_LOG_SCHEMA_VERSION = "pkgwhy.pip_install_decision_log.v1"
PipPolicy = Literal["standard", "strict"]


class PipInstallGateError(ValueError):
    """Raised when the pip install gate input is invalid."""


@dataclass(frozen=True)
class PipCommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


PipRunner = Callable[[list[str]], PipCommandResult]


def run_pip_install_gate(
    *,
    packages: list[str] | None = None,
    requirement_file: Path | None = None,
    policy: PipPolicy = "standard",
    pypi: bool = False,
    osv: bool = False,
    osv_cache_dir: Path | None = None,
    vulnerability_file: Path | None = None,
    download_artifacts: bool = False,
    override_review: bool = False,
    override_block: bool = False,
    override_reason: str | None = None,
    dry_run: bool = False,
    pip_runner: PipRunner | None = None,
    log_root: Path | None = None,
) -> PipInstallGateResult:
    """Run precheck before pip and call pip only when policy allows it."""

    packages = [package for package in (packages or []) if package]
    _validate_request(packages, requirement_file=requirement_file, policy=policy)

    try:
        precheck = _build_precheck(
            packages=packages,
            requirement_file=requirement_file,
            pypi=pypi,
            osv=osv,
            osv_cache_dir=osv_cache_dir,
            vulnerability_file=vulnerability_file,
            download_artifacts=download_artifacts,
        )
    except (PrecheckTargetError, PrecheckFileError) as exc:
        raise PipInstallGateError(str(exc)) from exc

    decision = _evaluate_install_decision(
        precheck,
        policy=policy,
        override_review=override_review,
        override_block=override_block,
        override_reason=override_reason,
    )
    command = _pip_command(packages, requirement_file=requirement_file)
    pip_returncode: int | None = None
    pip_invoked = False
    warnings = list(_precheck_warnings(precheck))
    reasons = list(decision.reasons)

    if decision.allowed:
        if dry_run:
            reasons.append("Dry run requested; pip was not invoked.")
        else:
            pip_invoked = True
            runner = pip_runner or _run_pip_command
            pip_result = runner(command)
            pip_returncode = pip_result.returncode
            if pip_result.returncode != 0:
                warnings.append("pip install command failed.")

    exit_code = _result_exit_code(decision=decision, pip_returncode=pip_returncode)
    result = PipInstallGateResult(
        target_type="requirements" if requirement_file is not None else "package",
        requested=packages,
        requirement_file=str(requirement_file) if requirement_file is not None else None,
        policy=policy,
        decision=_precheck_decision(precheck),
        risk_level=_precheck_risk(precheck),
        confidence=_precheck_confidence(precheck),
        precheck_exit_code=precheck.exit_code,
        exit_code=exit_code,
        pip_invoked=pip_invoked,
        pip_command=command if decision.allowed else [],
        pip_returncode=pip_returncode,
        dry_run=dry_run,
        override_used=decision.override_used,
        override_reason=override_reason if decision.override_used else None,
        reasons=reasons,
        warnings=sorted(set(warnings)),
        precheck=precheck,
    )
    log_path = write_pip_install_decision_log(result, log_root=log_root)
    if log_path is not None:
        result = result.model_copy(update={"log_path": str(log_path)})
    return result


@dataclass(frozen=True)
class InstallDecision:
    allowed: bool
    exit_code: int
    override_used: bool
    reasons: list[str]


def _validate_request(packages: list[str], *, requirement_file: Path | None, policy: str) -> None:
    if policy not in {"standard", "strict"}:
        raise PipInstallGateError("policy must be 'standard' or 'strict'")
    if requirement_file is not None and packages:
        raise PipInstallGateError("use either package targets or -r/--requirement, not both")
    if requirement_file is None and not packages:
        raise PipInstallGateError("pip install gate requires a package target or -r/--requirement file")
    if len(packages) > 1:
        raise PipInstallGateError("installing multiple package targets in one command is not supported yet")


def _build_precheck(
    *,
    packages: list[str],
    requirement_file: Path | None,
    pypi: bool,
    osv: bool,
    osv_cache_dir: Path | None,
    vulnerability_file: Path | None,
    download_artifacts: bool,
) -> PreInstallPackagePrecheckResult | PrecheckBatchResult:
    if requirement_file is not None:
        return build_requirements_precheck(
            requirement_file,
            pypi=pypi,
            osv=osv,
            osv_cache_dir=osv_cache_dir,
            vulnerability_file=vulnerability_file,
            download_artifacts=download_artifacts,
        )
    return build_package_precheck(
        packages[0],
        pypi=pypi,
        osv=osv,
        osv_cache_dir=osv_cache_dir,
        vulnerability_file=vulnerability_file,
        download_artifacts=download_artifacts,
    )


def _evaluate_install_decision(
    precheck: PreInstallPackagePrecheckResult | PrecheckBatchResult,
    *,
    policy: PipPolicy,
    override_review: bool,
    override_block: bool,
    override_reason: str | None,
) -> InstallDecision:
    decision = _precheck_decision(precheck)
    reasons = [f"Precheck decision: {decision.value}.", f"Precheck exit code: {precheck.exit_code}."]

    if precheck.exit_code == 4:
        reasons.append("Required precheck evidence was unavailable or incomplete; pip was not invoked.")
        return InstallDecision(allowed=False, exit_code=4, override_used=False, reasons=reasons)

    if decision == AgentDecision.ALLOW and precheck.exit_code == 0:
        if policy == "strict" and _precheck_warnings(precheck):
            reasons.append("Strict policy requires a clean allow result without warnings.")
            return InstallDecision(allowed=False, exit_code=1, override_used=False, reasons=reasons)
        reasons.append("Policy allows pip install after precheck.")
        return InstallDecision(allowed=True, exit_code=0, override_used=False, reasons=reasons)

    if decision in {AgentDecision.ALLOW_WITH_CAUTION, AgentDecision.REVIEW_MANUALLY}:
        if override_review:
            reasons.append("Explicit --override-review was used; pip install is allowed with a local decision log.")
            if override_reason:
                reasons.append(f"Override reason: {override_reason}")
            return InstallDecision(allowed=True, exit_code=0, override_used=True, reasons=reasons)
        reasons.append("Policy requires review before pip install.")
        return InstallDecision(allowed=False, exit_code=1, override_used=False, reasons=reasons)

    if decision in {AgentDecision.BLOCK, AgentDecision.SANDBOX_ONLY}:
        if override_block:
            reasons.append("Explicit --override-block was used; pip install is allowed with a local decision log.")
            if override_reason:
                reasons.append(f"Override reason: {override_reason}")
            return InstallDecision(allowed=True, exit_code=0, override_used=True, reasons=reasons)
        reasons.append("Policy blocks pip install.")
        return InstallDecision(allowed=False, exit_code=2, override_used=False, reasons=reasons)

    reasons.append("Policy could not classify the precheck result; pip was not invoked.")
    return InstallDecision(allowed=False, exit_code=3, override_used=False, reasons=reasons)


def _result_exit_code(*, decision: InstallDecision, pip_returncode: int | None) -> int:
    if not decision.allowed:
        return decision.exit_code
    if pip_returncode is None:
        return 0
    return 0 if pip_returncode == 0 else 3


def _pip_command(packages: list[str], *, requirement_file: Path | None) -> list[str]:
    command = [sys.executable, "-m", "pip", "install"]
    if requirement_file is not None:
        return [*command, "-r", str(requirement_file)]
    return [*command, packages[0]]


def _run_pip_command(command: list[str]) -> PipCommandResult:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    return PipCommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def _precheck_decision(precheck: PreInstallPackagePrecheckResult | PrecheckBatchResult) -> AgentDecision:
    return precheck.decision


def _precheck_risk(precheck: PreInstallPackagePrecheckResult | PrecheckBatchResult) -> RiskLevel:
    return precheck.risk_level


def _precheck_confidence(precheck: PreInstallPackagePrecheckResult | PrecheckBatchResult) -> Confidence:
    return precheck.confidence


def _precheck_warnings(precheck: PreInstallPackagePrecheckResult | PrecheckBatchResult) -> list[str]:
    return list(precheck.warnings)


def write_pip_install_decision_log(
    result: PipInstallGateResult,
    *,
    log_root: Path | None = None,
) -> Path | None:
    """Write a compact local pip gate decision log.

    Logging is best-effort and must not change the gate decision.
    """

    created_at = datetime.now(tz=UTC)
    target = result.requirement_file or "-".join(result.requested) or "unknown"
    root = log_root or config_dir() / "pip-install-decisions"
    target_dir = root / _safe_path_segment(target)
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    log_path = target_dir / f"{created_at.strftime('%Y%m%dT%H%M%S%fZ')}.json"
    payload = {
        "schema_version": PIP_INSTALL_DECISION_LOG_SCHEMA_VERSION,
        "created_at": created_at.isoformat(),
        "gate_schema_version": result.schema_version,
        "precheck_schema_version": result.precheck.schema_version,
        "target_type": result.target_type,
        "requested": result.requested,
        "requirement_file": result.requirement_file,
        "policy": result.policy,
        "decision": result.decision.value,
        "risk_level": result.risk_level.value,
        "confidence": result.confidence.value,
        "precheck_exit_code": result.precheck_exit_code,
        "exit_code": result.exit_code,
        "pip_invoked": result.pip_invoked,
        "pip_returncode": result.pip_returncode,
        "dry_run": result.dry_run,
        "override_used": result.override_used,
        "override_reason": result.override_reason,
        "reason_count": len(result.reasons),
        "warning_count": len(result.warnings),
        "reasons": list(result.reasons),
        "warnings": list(result.warnings),
    }
    try:
        log_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        return None
    return log_path


def _safe_path_segment(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip(".-_")
    return normalized or "unknown"

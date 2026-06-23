from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tarfile
import venv
from datetime import UTC, datetime
from pathlib import Path

from pkgwhy.core.models import (
    ToolArtifactType,
    ToolRunResult,
    ToolRunStatus,
)
from pkgwhy.policy.tool_execution import evaluate_tool_execution_policy
from pkgwhy.registry.local import current_registry
from pkgwhy.registry.tools import judge_tool, resolve_tool_entry

RUNNER_ISOLATION_WARNING = (
    "This run uses a Python virtual environment for dependency isolation. "
    "It does not fully sandbox operating-system permissions."
)
DEFAULT_RUN_TIMEOUT_SECONDS = 300


def run_local_tool(reference: str, *, non_interactive: bool = False) -> ToolRunResult:
    registry = current_registry()
    entry = resolve_tool_entry(reference, registry)
    judgement = judge_tool(reference)
    policy_result = evaluate_tool_execution_policy(judgement, non_interactive=non_interactive)
    if not policy_result.allowed:
        raise ValueError(f"Tool policy blocks execution: {' '.join(policy_result.reasons)}")
    manifest = judgement.manifest
    if manifest.artifact_type not in {ToolArtifactType.SCRIPT, ToolArtifactType.FOLDER}:
        raise ValueError(f"Unsupported tool artifact type for runner MVP: {manifest.artifact_type.value}")
    if manifest.dependencies:
        raise ValueError("Dependency installation is not implemented for pkgwhy run MVP.")
    entrypoint = Path(manifest.entrypoint)
    if entrypoint.is_absolute() or ".." in entrypoint.parts or entrypoint.suffix != ".py":
        raise ValueError(f"Unsupported entrypoint for runner MVP: {manifest.entrypoint}")

    tool_root = registry.path / "run-workspaces" / entry.owner / entry.name / entry.version
    venv_path = registry.path / "venvs" / entry.owner / entry.name / entry.version
    log_dir = registry.path / "execution-logs" / entry.owner / entry.name / entry.version
    bundle_path = registry.path / entry.bundle_path

    _prepare_workspace(bundle_path, tool_root)
    entrypoint_path = (tool_root / entrypoint).resolve()
    if not entrypoint_path.is_file() or tool_root.resolve() not in entrypoint_path.parents:
        raise ValueError(f"Entrypoint not found in tool bundle: {manifest.entrypoint}")
    python_path = _ensure_venv_python(venv_path)
    log_dir.mkdir(parents=True, exist_ok=True)

    started_at_dt = datetime.now(tz=UTC)
    command = [str(python_path), str(entrypoint_path)]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            cwd=tool_root,
            timeout=DEFAULT_RUN_TIMEOUT_SECONDS,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = _output_text(exc.stdout)
        stderr = _output_text(exc.stderr)
        timeout_message = f"Tool execution timed out after {DEFAULT_RUN_TIMEOUT_SECONDS} seconds."
        stderr = f"{stderr.rstrip()}\n{timeout_message}\n" if stderr else f"{timeout_message}\n"
    finished_at_dt = datetime.now(tz=UTC)
    status = ToolRunStatus.COMPLETED if exit_code == 0 else ToolRunStatus.FAILED
    result = ToolRunResult(
        tool=f"{entry.owner}/{entry.name}",
        owner=entry.owner,
        name=entry.name,
        version=entry.version,
        registry_name=registry.name,
        registry_path=registry.path,
        command=command,
        entrypoint=manifest.entrypoint,
        started_at=started_at_dt.isoformat(),
        finished_at=finished_at_dt.isoformat(),
        exit_code=exit_code,
        status=status,
        stdout=stdout,
        stderr=stderr,
        log_path=log_dir / f"{started_at_dt.strftime('%Y%m%dT%H%M%S%fZ')}.json",
        warning=RUNNER_ISOLATION_WARNING,
    )
    _write_execution_log(result)
    return result


def _prepare_workspace(bundle_path: Path, tool_root: Path) -> None:
    if tool_root.exists():
        shutil.rmtree(tool_root)
    tool_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(bundle_path, "r:gz") as archive:
        members = archive.getmembers()
        _validate_archive_members(members)
        try:
            archive.extractall(tool_root, members=members, filter="data")
        except TypeError:
            archive.extractall(tool_root, members=members)


def _validate_archive_members(members: list[tarfile.TarInfo]) -> None:
    for member in members:
        path = Path(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"Unsafe path in tool bundle: {member.name}")
        if member.issym() or member.islnk():
            raise ValueError(f"Links are not supported in runner bundles: {member.name}")


def _ensure_venv_python(venv_path: Path) -> Path:
    python_path = venv_path / ("Scripts/python.exe" if _is_windows_venv() else "bin/python")
    if not python_path.exists():
        venv.EnvBuilder(with_pip=False, clear=False).create(venv_path)
    if not python_path.exists():
        raise ValueError(f"Could not create runner virtual environment at {venv_path}")
    return python_path


def _is_windows_venv() -> bool:
    return sys.platform == "win32"


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _write_execution_log(result: ToolRunResult) -> None:
    result.log_path.parent.mkdir(parents=True, exist_ok=True)
    result.log_path.write_text(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n", encoding="utf-8")

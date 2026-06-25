from __future__ import annotations

import subprocess
import shutil
import sys
import time
from pathlib import Path

from pkgwhy.core.models import (
    AgentDecision,
    DynamicAnalysisResult,
    DynamicAnalysisStatus,
    DynamicFilesystemEvent,
    DynamicNetworkMode,
    DynamicProcessEvent,
)

EXPERIMENTAL_DYNAMIC_WARNING = "Experimental dynamic analysis is not a production sandbox."
STATIC_DEFAULT_WARNING = "Static package inspection remains the default pkgwhy review path."
HOST_EXECUTION_REFUSAL = "Refusing to run dynamic analysis for unknown package code on the host."


def build_unavailable_dynamic_result(
    target: str,
    *,
    container: bool,
    network: str,
) -> DynamicAnalysisResult:
    """Build a safe-fail dynamic result without executing the target."""
    warnings = [
        EXPERIMENTAL_DYNAMIC_WARNING,
        STATIC_DEFAULT_WARNING,
        HOST_EXECUTION_REFUSAL,
    ]
    limitations = [
        "No dynamic sandbox backend is implemented in this build.",
        "No process, filesystem, or network events were collected.",
        "Empty event lists are not proof that no behavior would occur in a real run.",
    ]
    sandbox_backend = "container" if container else "none"
    status = DynamicAnalysisStatus.BACKEND_UNAVAILABLE if container else DynamicAnalysisStatus.BLOCKED

    if network != DynamicNetworkMode.OFF.value:
        warnings.append("Only network mode 'off' is accepted in this pre-alpha skeleton.")
        limitations.append("Network-enabled dynamic analysis is not supported.")
        status = DynamicAnalysisStatus.BLOCKED
    elif container:
        docker_path = shutil.which("docker")
        if docker_path is None:
            warnings.append("Docker container backend is unavailable: docker executable was not found.")
        else:
            warnings.append("Docker executable was detected, but container execution is not implemented in this build.")
        limitations.append("Docker is detected by executable lookup only; pkgwhy does not invoke Docker in this build.")
    else:
        warnings.append("No sandbox backend selected. Host execution is not allowed.")

    return DynamicAnalysisResult(
        target=target,
        sandbox_backend=sandbox_backend,
        network_mode=DynamicNetworkMode.OFF,
        status=status,
        warnings=warnings,
        process_events=[],
        filesystem_events=[],
        network_events=[],
        decision=AgentDecision.BLOCK,
        limitations=limitations,
    )


def run_controlled_fixture(
    fixture_path: Path,
    *,
    fixture_root: Path,
    scratch_dir: Path,
    timeout_seconds: float = 5.0,
) -> DynamicAnalysisResult:
    """Run a known local fixture for tests without enabling arbitrary package execution."""
    resolved_fixture = fixture_path.resolve()
    resolved_fixture_root = fixture_root.resolve()
    if resolved_fixture_root not in resolved_fixture.parents:
        raise ValueError("controlled fixture must live under fixture_root")
    if resolved_fixture.suffix != ".py" or not resolved_fixture.is_file():
        raise ValueError("controlled fixture must be a Python file")

    scratch_dir.mkdir(parents=True, exist_ok=True)
    before = _snapshot_scratch(scratch_dir)
    started_at = time.monotonic()
    completed = subprocess.run(
        [sys.executable, str(resolved_fixture)],
        cwd=scratch_dir,
        env={"PYTHONIOENCODING": "utf-8"},
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    duration_ms = int((time.monotonic() - started_at) * 1000)
    after = _snapshot_scratch(scratch_dir)
    status = DynamicAnalysisStatus.COMPLETED if completed.returncode == 0 else DynamicAnalysisStatus.FAILED
    decision = AgentDecision.ALLOW_WITH_CAUTION if completed.returncode == 0 else AgentDecision.BLOCK
    warnings = [
        "Controlled fixture execution only; this is not a sandbox for unknown package code.",
        "No network monitor is implemented for controlled fixture execution.",
    ]
    limitations = [
        "Execution was limited to a caller-provided local fixture path.",
        "Only scratch filesystem changes are compared.",
        "No process-tree or network telemetry is collected.",
    ]
    if completed.stderr:
        warnings.append("Controlled fixture wrote to stderr; stderr content is intentionally not included in the result.")

    return DynamicAnalysisResult(
        target=resolved_fixture.name,
        sandbox_backend="controlled_fixture",
        status=status,
        warnings=warnings,
        process_events=[
            DynamicProcessEvent(
                command=[sys.executable, resolved_fixture.name],
                exit_code=completed.returncode,
                duration_ms=duration_ms,
            )
        ],
        filesystem_events=_filesystem_events(before, after),
        network_events=[],
        decision=decision,
        limitations=limitations,
    )


def _snapshot_scratch(root: Path) -> dict[str, int]:
    snapshot: dict[str, int] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            relative_path = path.relative_to(root).as_posix()
            snapshot[relative_path] = path.stat().st_mtime_ns
        except OSError:
            continue
    return snapshot


def _filesystem_events(before: dict[str, int], after: dict[str, int]) -> list[DynamicFilesystemEvent]:
    events: list[DynamicFilesystemEvent] = []
    for path, mtime_ns in sorted(after.items()):
        if path not in before:
            events.append(DynamicFilesystemEvent(path=path, action="created"))
        elif before[path] != mtime_ns:
            events.append(DynamicFilesystemEvent(path=path, action="modified"))
    return events

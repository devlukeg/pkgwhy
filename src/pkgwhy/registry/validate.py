from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from pkgwhy.core.models import (
    AgentDecision,
    RiskLevel,
    ToolArtifactType,
    ToolManifest,
    ToolValidationIssue,
    ToolValidationResult,
)
from pkgwhy.inspection.files import analyze_file_signals
from pkgwhy.inspection.python_static import analyze_python_files
from pkgwhy.registry.manifest import MANIFEST_FILENAME, read_tool_manifest
from pkgwhy.registry.publish import EXCLUDED_DIRS

SUPPORTED_DECLARED_PERMISSIONS = {
    "browser_code",
    "credentials",
    "deserialisation",
    "dynamic_code",
    "environment",
    "filesystem_read",
    "filesystem_write",
    "native_code",
    "network",
    "package_manager",
    "shell",
    "subprocess",
}
CAPABILITY_PERMISSION_LABELS = {
    "Browser or JavaScript code present": {"browser_code"},
    "Credential or token access patterns": {"credentials"},
    "Deserialisation risk signals": {"deserialisation"},
    "Dynamic code execution signals": {"dynamic_code"},
    "Dynamic import signals": {"dynamic_code"},
    "Encoded payload handling signals": {"dynamic_code"},
    "Environment variable access signals": {"environment"},
    "Filesystem access signals": {"filesystem_read"},
    "JavaScript dynamic code execution signals": {"dynamic_code", "browser_code"},
    "JavaScript obfuscation signals": {"browser_code"},
    "Native compiled code present": {"native_code"},
    "Network access signals": {"network"},
    "Package manager manipulation signals": {"package_manager"},
    "Shell script files present": {"shell"},
    "Subprocess or shell execution signals": {"subprocess"},
    "WASM binary code present": {"native_code"},
}


@dataclass(frozen=True)
class ToolStaticSignals:
    detected_capabilities: list[str]
    warnings: list[str]
    evidence: list[str]


def validate_tool_source(path: Path) -> ToolValidationResult:
    requested_source = path.expanduser()
    target = str(path)
    if requested_source.is_symlink():
        return _result(
            target=target,
            target_type="path",
            manifest=None,
            issues=[
                ToolValidationIssue(
                    code="source_symlink",
                    severity="error",
                    message=f"Tool source path must not be a symlink: {requested_source}",
                    path=str(requested_source),
                    suggested_fix="Pass the real tool folder or script path instead of a symlink.",
                )
            ],
        )

    source = requested_source.resolve()
    if not source.exists():
        return _result(
            target=target,
            target_type="path",
            manifest=None,
            issues=[
                ToolValidationIssue(
                    code="source_missing",
                    severity="error",
                    message=f"Tool source path does not exist: {source}",
                    path=str(source),
                    suggested_fix="Pass an existing Python script or folder with pkgwhy.toml.",
                )
            ],
            exit_code=3,
        )

    if source.is_file():
        return _validate_script_source(source, target=target)
    if source.is_dir():
        return _validate_folder_source(source, target=target)

    return _result(
        target=target,
        target_type="path",
        manifest=None,
        issues=[
            ToolValidationIssue(
                code="unsupported_source_type",
                severity="error",
                message="Tool source must be a Python script or a folder with pkgwhy.toml.",
                path=str(source),
                suggested_fix="Pass a .py file or a directory containing pkgwhy.toml.",
            )
        ],
        exit_code=3,
    )


def analyze_tool_files(paths: list[Path], entrypoint: str) -> ToolStaticSignals:
    file_analysis = analyze_file_signals(paths, [entrypoint] if entrypoint else [])
    python_analysis = analyze_python_files(paths)
    capabilities = sorted(set(file_analysis.detected_capabilities) | set(python_analysis.detected_capabilities))
    warnings = [*file_analysis.warnings, *python_analysis.warnings]
    evidence = [*file_analysis.evidence, *python_analysis.evidence]
    return ToolStaticSignals(detected_capabilities=capabilities, warnings=warnings, evidence=evidence)


def _validate_script_source(source: Path, *, target: str) -> ToolValidationResult:
    issues: list[ToolValidationIssue] = []
    if source.suffix != ".py":
        issues.append(
            ToolValidationIssue(
                code="unsupported_script_type",
                severity="error",
                message="Single-file tools must be Python .py files.",
                path=str(source),
                suggested_fix="Pass a .py script or use a folder with pkgwhy.toml.",
            )
        )
    if source.is_symlink():
        issues.append(
            ToolValidationIssue(
                code="entrypoint_symlink",
                severity="error",
                message="Tool entrypoint must not be a symlink.",
                path=str(source),
                suggested_fix="Use a regular Python file as the entrypoint.",
            )
        )
    manifest = ToolManifest(
        name=source.stem,
        owner="local",
        version="0.1.0",
        description="Local Python script validated with pkgwhy.",
        artifact_type=ToolArtifactType.SCRIPT,
        entrypoint=source.name,
        declared_permissions=[],
    )
    static_signals = analyze_tool_files([source], source.name)
    _add_permission_warnings(issues, manifest, static_signals.detected_capabilities)
    return _result(
        target=target,
        target_type="tool_script",
        manifest=manifest,
        issues=issues,
        detected_capabilities=static_signals.detected_capabilities,
        static_warnings=static_signals.warnings,
        static_evidence=static_signals.evidence,
    )


def _validate_folder_source(source: Path, *, target: str) -> ToolValidationResult:
    issues: list[ToolValidationIssue] = []
    manifest: ToolManifest | None = None
    try:
        manifest = read_tool_manifest(source)
    except ValueError as exc:
        issues.append(
            ToolValidationIssue(
                code="manifest_invalid",
                severity="error",
                message=str(exc),
                path=str(source / MANIFEST_FILENAME),
                suggested_fix="Fix pkgwhy.toml so it contains a valid [tool] table and supported policy values.",
            )
        )

    files = _collect_source_files(source, issues)
    static_signals = analyze_tool_files(files, manifest.entrypoint if manifest else "")
    if manifest is not None:
        _validate_entrypoint(source, manifest, issues)
        _validate_declared_permissions(manifest, issues)
        _validate_non_interactive_policy(manifest, issues)
        _add_permission_warnings(issues, manifest, static_signals.detected_capabilities)

    return _result(
        target=target,
        target_type="tool_folder",
        manifest=manifest,
        manifest_path=str(source / MANIFEST_FILENAME),
        issues=issues,
        detected_capabilities=static_signals.detected_capabilities,
        static_warnings=static_signals.warnings,
        static_evidence=static_signals.evidence,
    )


def _collect_source_files(source: Path, issues: list[ToolValidationIssue]) -> list[Path]:
    files: list[Path] = []
    for root, dirnames, filenames in os.walk(source, followlinks=False):
        root_path = Path(root)
        kept_dirnames: list[str] = []
        for dirname in sorted(dirnames):
            child = root_path / dirname
            relative = child.relative_to(source)
            if dirname in EXCLUDED_DIRS:
                issues.append(
                    ToolValidationIssue(
                        code="unsupported_path_skipped",
                        severity="warning",
                        message=f"Unsupported path is skipped by tool bundling: {relative}",
                        path=str(relative),
                        suggested_fix="Remove generated, virtualenv, or VCS paths before publishing.",
                    )
                )
                continue
            if child.is_symlink():
                issues.append(
                    ToolValidationIssue(
                        code="symlink_unsupported",
                        severity="error",
                        message=f"Symlinks are not supported in tool bundles: {relative}",
                        path=str(relative),
                        suggested_fix="Replace symlinks with regular files inside the tool folder.",
                    )
                )
                continue
            kept_dirnames.append(dirname)
        dirnames[:] = kept_dirnames

        for filename in sorted(filenames):
            child = root_path / filename
            relative = child.relative_to(source)
            if child.is_symlink():
                issues.append(
                    ToolValidationIssue(
                        code="symlink_unsupported",
                        severity="error",
                        message=f"Symlinks are not supported in tool bundles: {relative}",
                        path=str(relative),
                        suggested_fix="Replace symlinks with regular files inside the tool folder.",
                    )
                )
                continue
            if child.is_file():
                files.append(child)
    return files


def _validate_entrypoint(source: Path, manifest: ToolManifest, issues: list[ToolValidationIssue]) -> None:
    entrypoint = Path(manifest.entrypoint)
    if entrypoint.is_absolute() or ".." in entrypoint.parts:
        issues.append(
            ToolValidationIssue(
                code="entrypoint_path_unsafe",
                severity="error",
                message="Tool entrypoint must stay inside the tool folder.",
                path=manifest.entrypoint,
                suggested_fix="Use a relative entrypoint path inside the tool folder.",
            )
        )
        return
    candidate = (source / entrypoint).resolve()
    if not candidate.is_relative_to(source.resolve()):
        issues.append(
            ToolValidationIssue(
                code="entrypoint_path_unsafe",
                severity="error",
                message="Tool entrypoint escapes the tool folder.",
                path=manifest.entrypoint,
                suggested_fix="Use a relative entrypoint path inside the tool folder.",
            )
        )
        return
    if not candidate.exists():
        issues.append(
            ToolValidationIssue(
                code="entrypoint_missing",
                severity="error",
                message=f"Tool entrypoint does not exist: {manifest.entrypoint}",
                path=manifest.entrypoint,
                suggested_fix="Create the entrypoint file or update pkgwhy.toml.",
            )
        )
        return
    if candidate.is_symlink():
        issues.append(
            ToolValidationIssue(
                code="entrypoint_symlink",
                severity="error",
                message="Tool entrypoint must not be a symlink.",
                path=manifest.entrypoint,
                suggested_fix="Use a regular file as the entrypoint.",
            )
        )
    elif not candidate.is_file():
        issues.append(
            ToolValidationIssue(
                code="entrypoint_not_file",
                severity="error",
                message="Tool entrypoint must be a file.",
                path=manifest.entrypoint,
                suggested_fix="Point entrypoint at a Python file or executable script file.",
            )
        )


def _validate_declared_permissions(manifest: ToolManifest, issues: list[ToolValidationIssue]) -> None:
    for permission in manifest.declared_permissions:
        if permission not in SUPPORTED_DECLARED_PERMISSIONS:
            issues.append(
                ToolValidationIssue(
                    code="declared_permission_unknown",
                    severity="warning",
                    message=f"Declared permission is not a recognized pkgwhy permission label: {permission}",
                    path=MANIFEST_FILENAME,
                    suggested_fix="Use a known permission label or document why this custom label is needed.",
                )
            )


def _validate_non_interactive_policy(manifest: ToolManifest, issues: list[ToolValidationIssue]) -> None:
    if manifest.agent.non_interactive_decision in {AgentDecision.ALLOW, AgentDecision.ALLOW_WITH_CAUTION}:
        issues.append(
            ToolValidationIssue(
                code="non_interactive_allows_execution",
                severity="warning",
                message=(
                    "Manifest allows non-interactive agent execution; verify this is intentional for the tool risk."
                ),
                path=MANIFEST_FILENAME,
                suggested_fix="Use review_manually or block unless this tool is intentionally agent-runnable.",
            )
        )


def _add_permission_warnings(
    issues: list[ToolValidationIssue],
    manifest: ToolManifest,
    detected_capabilities: list[str],
) -> None:
    expected_permissions = _expected_permissions_for_capabilities(detected_capabilities)
    missing_permissions = sorted(expected_permissions - set(manifest.declared_permissions))
    if missing_permissions:
        issues.append(
            ToolValidationIssue(
                code="declared_permissions_missing",
                severity="warning",
                message="Static capability signals are not covered by declared permissions: "
                + ", ".join(missing_permissions),
                path=MANIFEST_FILENAME,
                suggested_fix="Declare the expected tool permissions or review why the signals are acceptable.",
            )
        )


def _expected_permissions_for_capabilities(detected_capabilities: list[str]) -> set[str]:
    expected: set[str] = set()
    for capability in detected_capabilities:
        expected.update(CAPABILITY_PERMISSION_LABELS.get(capability, set()))
    return expected


def _result(
    *,
    target: str,
    target_type: str,
    manifest: ToolManifest | None,
    issues: list[ToolValidationIssue],
    manifest_path: str | None = None,
    detected_capabilities: list[str] | None = None,
    static_warnings: list[str] | None = None,
    static_evidence: list[str] | None = None,
    exit_code: int | None = None,
) -> ToolValidationResult:
    errors = [issue.message for issue in issues if issue.severity == "error"]
    warnings = [issue.message for issue in issues if issue.severity == "warning"]
    warnings.extend(static_warnings or [])
    valid = not errors
    if errors:
        decision = AgentDecision.BLOCK
        risk_level = RiskLevel.HIGH
    elif warnings:
        decision = AgentDecision.ALLOW_WITH_CAUTION
        risk_level = RiskLevel.MEDIUM
    else:
        decision = AgentDecision.ALLOW
        risk_level = RiskLevel.LOW
    return ToolValidationResult(
        target=target,
        target_type=target_type,
        valid=valid,
        decision=decision,
        risk_level=risk_level,
        manifest=manifest,
        manifest_path=manifest_path,
        entrypoint=manifest.entrypoint if manifest else None,
        declared_permissions=manifest.declared_permissions if manifest else [],
        detected_capabilities=detected_capabilities or [],
        issues=issues,
        errors=errors,
        warnings=warnings,
        evidence=static_evidence or ["Validated local tool source without executing tool code."],
        exit_code=exit_code,
        policy={
            "executes_tool_code": False,
            "writes_to_registry": False,
            "symlinks_supported": False,
        },
    )

from __future__ import annotations

import hashlib
import json
import tarfile
import tempfile
from pathlib import Path

from pydantic import ValidationError

from pkgwhy.core.models import (
    AgentDecision,
    Confidence,
    HashStatus,
    RegistryEntry,
    RegistryToolEntry,
    RiskLevel,
    ToolJudgement,
    ToolManifest,
    ToolTrustState,
)
from pkgwhy.registry.local import current_registry, load_registry_index
from pkgwhy.registry.validate import analyze_tool_files


def judge_tool(reference: str) -> ToolJudgement:
    registry = current_registry()
    entry = resolve_tool_entry(reference, registry)
    manifest = _load_manifest(registry.path, entry)
    hash_status = _verify_hash(registry.path, entry)
    warnings: list[str] = ["Signature verification is not implemented yet."]
    detected_capabilities: list[str] = []
    static_evidence: list[str] = []

    if hash_status == HashStatus.VERIFIED:
        risk = RiskLevel.MEDIUM
        decision = AgentDecision.REVIEW_MANUALLY if manifest.security.requires_human_approval else AgentDecision.ALLOW_WITH_CAUTION
        reason = "Tool bundle hash matches the local registry index."
        recommendation = "Review declared permissions and manifest metadata before running this private tool."
    elif hash_status == HashStatus.MISSING:
        risk = RiskLevel.UNKNOWN
        decision = AgentDecision.REVIEW_MANUALLY
        reason = "Tool bundle is missing from the local registry."
        recommendation = "Restore or republish the bundle before running this tool."
        warnings.append("Bundle file is missing.")
    else:
        risk = RiskLevel.HIGH
        decision = AgentDecision.BLOCK
        reason = "Tool bundle hash does not match the local registry index."
        recommendation = "Block use until a human verifies or republishes the tool."
        warnings.append("Bundle hash mismatch.")

    if hash_status == HashStatus.VERIFIED:
        bundle_path = _validate_registry_path(registry.path, entry.bundle_path, entry)
        static_signals = _analyze_verified_bundle(bundle_path, manifest)
        detected_capabilities = static_signals.detected_capabilities
        warnings.extend(static_signals.warnings)
        static_evidence = static_signals.evidence

    evidence = [reason]
    evidence.extend(static_evidence)
    trust_evidence = f"Registry trust state is {entry.trust_state.value}."
    evidence.append(trust_evidence)
    if entry.trust_state == ToolTrustState.BLOCKED:
        risk = RiskLevel.CRITICAL
        decision = AgentDecision.BLOCK
        reason = "Tool is blocked in the local registry trust state."
        recommendation = "Do not run this tool unless a human changes the registry trust state."
        warnings.append("Registry trust state blocks this tool.")
        evidence.append(reason)
    elif entry.trust_state == ToolTrustState.QUARANTINED:
        risk = RiskLevel.HIGH
        decision = AgentDecision.BLOCK
        reason = "Tool is quarantined in the local registry trust state."
        recommendation = "Do not run this tool until a human reviews it and changes the registry trust state."
        warnings.append("Registry trust state quarantines this tool.")
        evidence.append(reason)

    return ToolJudgement(
        tool=f"{entry.owner}/{entry.name}",
        owner=entry.owner,
        name=entry.name,
        version=entry.version,
        decision=decision,
        risk_level=risk,
        confidence=Confidence.MEDIUM if hash_status == HashStatus.VERIFIED else Confidence.LOW,
        reason=reason,
        requires_human_approval=manifest.security.requires_human_approval,
        manifest=manifest,
        declared_permissions=manifest.declared_permissions,
        detected_capabilities=detected_capabilities,
        hash_status=hash_status,
        trust_state=entry.trust_state,
        warnings=warnings,
        recommendation=recommendation,
        evidence=evidence,
    )


def resolve_tool_entry(reference: str, registry: RegistryEntry | None = None) -> RegistryToolEntry:
    active_registry = registry or current_registry()
    index = load_registry_index(active_registry.path, strict=True)
    owner, name = _parse_reference(reference)
    matches = [
        entry
        for entry in index.tools
        if entry.name == name and (owner is None or entry.owner == owner)
    ]
    if not matches:
        raise ValueError(f"Tool is not published in the current registry: {reference}")
    if owner is None and len({entry.owner for entry in matches}) > 1:
        raise ValueError(f"Tool reference is ambiguous; include owner: {reference}")
    return sorted(matches, key=lambda entry: entry.published_at, reverse=True)[0]


def _parse_reference(reference: str) -> tuple[str | None, str]:
    parts = reference.split("/", maxsplit=1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return None, reference


def _load_manifest(registry_path: Path, entry: RegistryToolEntry) -> ToolManifest:
    manifest_path = _validate_registry_path(registry_path, entry.manifest_path, entry)
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        return ToolManifest.model_validate(data)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ValueError(f"Could not read stored tool manifest for {entry.owner}/{entry.name}") from exc


def _verify_hash(registry_path: Path, entry: RegistryToolEntry) -> HashStatus:
    bundle_path = _validate_registry_path(registry_path, entry.bundle_path, entry)
    digest = hashlib.sha256()
    try:
        with bundle_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except FileNotFoundError:
        return HashStatus.MISSING
    if digest.hexdigest() != entry.sha256:
        return HashStatus.MISMATCH
    return HashStatus.VERIFIED


def _analyze_verified_bundle(bundle_path: Path, manifest: ToolManifest):
    with tempfile.TemporaryDirectory(prefix="pkgwhy-tool-static-") as temp_dir:
        root = Path(temp_dir)
        extracted_paths: list[Path] = []
        try:
            with tarfile.open(bundle_path, "r:gz") as archive:
                for member in archive.getmembers()[:500]:
                    member_path = Path(member.name)
                    if member_path.is_absolute() or ".." in member_path.parts:
                        continue
                    if not member.isfile():
                        continue
                    target = (root / member_path).resolve()
                    if not target.is_relative_to(root):
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        continue
                    with source, target.open("wb") as handle:
                        handle.write(source.read(1_000_000))
                    extracted_paths.append(target)
        except (OSError, tarfile.TarError):
            return analyze_tool_files([], manifest.entrypoint)
        return analyze_tool_files(extracted_paths, manifest.entrypoint)


def _validate_registry_path(registry_path: Path, entry_path: str, entry: RegistryToolEntry) -> Path:
    registry_root = registry_path.resolve()
    candidate = (registry_root / entry_path).resolve()
    if not candidate.is_relative_to(registry_root):
        raise ValueError(f"Registry entry path escapes registry root for {entry.owner}/{entry.name}: {entry_path}")
    return candidate

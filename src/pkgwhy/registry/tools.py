from __future__ import annotations

import hashlib
import json
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
)
from pkgwhy.registry.local import current_registry, load_registry_index


def judge_tool(reference: str) -> ToolJudgement:
    registry = current_registry()
    entry = resolve_tool_entry(reference, registry)
    manifest = _load_manifest(registry.path, entry)
    hash_status = _verify_hash(registry.path, entry)
    warnings: list[str] = ["Signature verification is not implemented yet."]
    detected_capabilities: list[str] = []

    if hash_status == HashStatus.VERIFIED:
        risk = RiskLevel.MEDIUM
        decision = AgentDecision.REVIEW_MANUALLY if manifest.security.requires_human_approval else AgentDecision.ALLOW_WITH_CAUTION
        reason = "Tool bundle hash matches the local registry index."
        recommendation = "Review declared permissions and manifest metadata before running this private tool."
    elif hash_status == HashStatus.MISSING:
        risk = RiskLevel.UNKNOWN
        decision = AgentDecision.REVIEW_MANUALLY
        reason = "Tool bundle is missing from the local registry."
        recommendation = "Do not run until the bundle is restored or republished."
        warnings.append("Bundle file is missing.")
    else:
        risk = RiskLevel.HIGH
        decision = AgentDecision.BLOCK
        reason = "Tool bundle hash does not match the local registry index."
        recommendation = "Block use until a human verifies or republishes the tool."
        warnings.append("Bundle hash mismatch.")

    if not detected_capabilities:
        warnings.append("Static capability detection for tool bundles is not implemented yet.")

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
        warnings=warnings,
        recommendation=recommendation,
    )


def resolve_tool_entry(reference: str, registry: RegistryEntry | None = None) -> RegistryToolEntry:
    active_registry = registry or current_registry()
    index = load_registry_index(active_registry.path)
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


def _validate_registry_path(registry_path: Path, entry_path: str, entry: RegistryToolEntry) -> Path:
    registry_root = registry_path.resolve()
    candidate = (registry_root / entry_path).resolve()
    if not candidate.is_relative_to(registry_root):
        raise ValueError(f"Registry entry path escapes registry root for {entry.owner}/{entry.name}: {entry_path}")
    return candidate

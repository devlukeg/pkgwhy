from __future__ import annotations

import hashlib
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path

from pkgwhy.core.models import PublishResult, RegistryToolEntry, ToolArtifactType, ToolManifest
from pkgwhy.registry.local import current_registry, load_registry_index, save_registry_index
from pkgwhy.registry.manifest import read_tool_manifest

EXCLUDED_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "__pycache__"}


def publish_local_tool(path: Path) -> PublishResult:
    source = path.expanduser().resolve()
    if not source.exists():
        raise ValueError(f"Publish path does not exist: {source}")

    registry = current_registry()
    manifest = _manifest_for_source(source)
    bundle_path = _bundle_path(registry.path, manifest)
    manifest_path = _manifest_path(registry.path, manifest)
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    _write_bundle(source, bundle_path)
    sha256 = _sha256_file(bundle_path)
    manifest_path.write_text(
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _update_index(registry.path, manifest, bundle_path, manifest_path, sha256)

    return PublishResult(
        manifest=manifest,
        registry_name=registry.name,
        registry_path=registry.path,
        bundle_path=bundle_path,
        manifest_path=manifest_path,
        sha256=sha256,
    )


def _manifest_for_source(source: Path) -> ToolManifest:
    if source.is_file() and source.suffix == ".py":
        return ToolManifest(
            name=source.stem,
            owner="local",
            version="0.1.0",
            description="Local Python script published with pkgwhy.",
            artifact_type=ToolArtifactType.SCRIPT,
            entrypoint=source.name,
            declared_permissions=[],
        )
    if source.is_dir():
        return read_tool_manifest(source)
    raise ValueError("Publish path must be a Python script or a folder with pkgwhy.toml")


def _bundle_path(registry_path: Path, manifest: ToolManifest) -> Path:
    return (
        registry_path
        / "bundles"
        / manifest.owner
        / manifest.name
        / manifest.version
        / f"{manifest.name}-{manifest.version}.tar.gz"
    )


def _manifest_path(registry_path: Path, manifest: ToolManifest) -> Path:
    return registry_path / "manifests" / manifest.owner / manifest.name / manifest.version / "manifest.json"


def _write_bundle(source: Path, bundle_path: Path) -> None:
    with tarfile.open(bundle_path, "w:gz") as archive:
        if source.is_file():
            archive.add(source, arcname=source.name)
            return
        for child in sorted(source.rglob("*")):
            if _should_skip(child):
                continue
            archive.add(child, arcname=child.relative_to(source))


def _should_skip(path: Path) -> bool:
    return any(part in EXCLUDED_DIRS for part in path.parts)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _update_index(
    registry_path: Path,
    manifest: ToolManifest,
    bundle_path: Path,
    manifest_path: Path,
    sha256: str,
) -> None:
    index = load_registry_index(registry_path)
    published_at = datetime.now(tz=UTC).isoformat()
    entry = RegistryToolEntry(
        name=manifest.name,
        owner=manifest.owner,
        version=manifest.version,
        artifact_type=manifest.artifact_type,
        entrypoint=manifest.entrypoint,
        bundle_path=str(bundle_path.relative_to(registry_path)),
        sha256=sha256,
        manifest_path=str(manifest_path.relative_to(registry_path)),
        published_at=published_at,
    )
    index.tools = [
        existing
        for existing in index.tools
        if not (existing.owner == entry.owner and existing.name == entry.name and existing.version == entry.version)
    ]
    index.tools.append(entry)
    save_registry_index(registry_path, index)

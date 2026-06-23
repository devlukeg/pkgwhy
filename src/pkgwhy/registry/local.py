from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from pkgwhy.core.models import RegistryConfig, RegistryEntry, RegistryIndex

CONFIG_ENV_VAR = "PKGWHY_CONFIG_HOME"
CONFIG_FILENAME = "registries.json"
REGISTRY_INDEX_FILENAME = "pkgwhy-registry.json"
DEFAULT_REGISTRY_NAME = "local"


def config_dir() -> Path:
    override = os.environ.get(CONFIG_ENV_VAR)
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "pkgwhy"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "pkgwhy"
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return Path(xdg_config_home) / "pkgwhy"
    return Path.home() / ".config" / "pkgwhy"


def config_path() -> Path:
    return config_dir() / CONFIG_FILENAME


def registry_index_path(path: Path) -> Path:
    return path / REGISTRY_INDEX_FILENAME


def load_registry_index(path: Path) -> RegistryIndex:
    target = registry_index_path(path)
    if not target.exists():
        return RegistryIndex()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        return RegistryIndex.model_validate(data)
    except (OSError, json.JSONDecodeError, ValidationError):
        return RegistryIndex()


def save_registry_index(path: Path, index: RegistryIndex) -> None:
    target = registry_index_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(index.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    temp_path = target.with_name(f".{target.name}.tmp")
    temp_path.write_text(content, encoding="utf-8")
    temp_path.replace(target)


def load_registry_config(path: Path | None = None) -> RegistryConfig:
    target = path or config_path()
    if not target.exists():
        return RegistryConfig()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        return RegistryConfig.model_validate(data)
    except (OSError, json.JSONDecodeError, ValidationError):
        return RegistryConfig()


def save_registry_config(config: RegistryConfig, path: Path | None = None) -> None:
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(config.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    temp_path = target.with_name(f".{target.name}.tmp")
    temp_path.write_text(content, encoding="utf-8")
    temp_path.replace(target)


def init_local_registry(path: Path, name: str = DEFAULT_REGISTRY_NAME) -> RegistryEntry:
    registry_path = path.expanduser().resolve()
    registry_path.mkdir(parents=True, exist_ok=True)
    index_path = registry_index_path(registry_path)
    if not index_path.exists():
        index_path.write_text(
            json.dumps(RegistryIndex().model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    config = load_registry_config()
    config.registries[name] = str(registry_path)
    config.current_registry = name
    save_registry_config(config)
    return RegistryEntry(name=name, path=registry_path, is_current=True, index_exists=True)


def add_registry(name: str, path: Path) -> RegistryEntry:
    registry_path = path.expanduser().resolve()
    if not registry_path.is_dir():
        raise ValueError(f"Registry path does not exist or is not a directory: {registry_path}")

    index_exists = registry_index_path(registry_path).exists()
    config = load_registry_config()
    if name in config.registries:
        raise ValueError(f"A registry with this name already exists: {name}")
    config.registries[name] = str(registry_path)
    if config.current_registry is None:
        config.current_registry = name
    save_registry_config(config)
    return RegistryEntry(
        name=name,
        path=registry_path,
        is_current=config.current_registry == name,
        index_exists=index_exists,
    )


def use_registry(name: str) -> RegistryEntry:
    config = load_registry_config()
    registry_path_text = config.registries.get(name)
    if registry_path_text is None:
        raise ValueError(f"Registry is not configured: {name}")

    config.current_registry = name
    save_registry_config(config)
    registry_path = Path(registry_path_text)
    return RegistryEntry(
        name=name,
        path=registry_path,
        is_current=True,
        index_exists=registry_index_path(registry_path).exists(),
    )


def current_registry() -> RegistryEntry:
    config = load_registry_config()
    if config.current_registry is None:
        raise ValueError("No current registry is configured. Run 'pkgwhy registry init <path>' first.")
    return use_registry(config.current_registry)


def list_registries() -> list[RegistryEntry]:
    config = load_registry_config()
    entries: list[RegistryEntry] = []
    for name, path_text in sorted(config.registries.items()):
        registry_path = Path(path_text)
        entries.append(
            RegistryEntry(
                name=name,
                path=registry_path,
                is_current=config.current_registry == name,
                index_exists=registry_index_path(registry_path).exists(),
            )
        )
    return entries

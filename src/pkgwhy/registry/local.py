from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from pkgwhy.core.models import RegistryConfig, RegistryEntry, RegistryIndex

CONFIG_ENV_VAR = "PKGWHY_CONFIG_HOME"
CONFIG_FILENAME = "registries.json"
REGISTRY_INDEX_FILENAME = "pkgwhy-registry.json"
DEFAULT_REGISTRY_NAME = "local"


def config_dir() -> Path:
    override = os.environ.get(CONFIG_ENV_VAR)
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "pkgwhy"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "pkgwhy"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "pkgwhy"


def config_path() -> Path:
    return config_dir() / CONFIG_FILENAME


def registry_index_path(path: Path) -> Path:
    return path / REGISTRY_INDEX_FILENAME


def load_registry_config(path: Path | None = None) -> RegistryConfig:
    target = path or config_path()
    if not target.exists():
        return RegistryConfig()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return RegistryConfig()
    return RegistryConfig.model_validate(data)


def save_registry_config(config: RegistryConfig, path: Path | None = None) -> None:
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(config.model_dump(mode="json"), indent=2, sort_keys=True) + "\n", encoding="utf-8")


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

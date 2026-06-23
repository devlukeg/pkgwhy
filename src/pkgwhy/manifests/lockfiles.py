from __future__ import annotations

import logging
import tomllib
from pathlib import Path

from pkgwhy.metadata.installed import normalize_package_name

logger = logging.getLogger(__name__)


def read_uv_lock_dependencies(path: Path) -> set[str]:
    return _read_toml_lock_packages(path)


def read_poetry_lock_dependencies(path: Path) -> set[str]:
    return _read_toml_lock_packages(path)


def read_lockfile_dependencies(project_root: Path) -> dict[str, set[str]]:
    lockfiles: dict[str, set[str]] = {}
    uv_lock = project_root / "uv.lock"
    poetry_lock = project_root / "poetry.lock"
    uv_dependencies = read_uv_lock_dependencies(uv_lock)
    poetry_dependencies = read_poetry_lock_dependencies(poetry_lock)
    if uv_dependencies:
        lockfiles["uv.lock"] = uv_dependencies
    if poetry_dependencies:
        lockfiles["poetry.lock"] = poetry_dependencies
    return lockfiles


def _read_toml_lock_packages(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        logger.debug("Unable to parse lockfile %s: %s", path, exc)
        return set()

    names: set[str] = set()
    packages = data.get("package", [])
    if isinstance(packages, list):
        for package in packages:
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            if isinstance(name, str):
                names.add(normalize_package_name(name))
    return names

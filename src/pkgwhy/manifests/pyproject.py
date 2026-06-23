from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name


def read_pyproject_dependencies(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return set()

    names: set[str] = set()
    project = data.get("project", {})
    for dependency in project.get("dependencies", []):
        _add_requirement_name(names, dependency)

    optional = project.get("optional-dependencies", {})
    if isinstance(optional, dict):
        for dependencies in optional.values():
            if not isinstance(dependencies, list):
                continue
            for dependency in dependencies:
                _add_requirement_name(names, dependency)
    return names


def _add_requirement_name(names: set[str], value: str) -> None:
    try:
        names.add(canonicalize_name(Requirement(value).name))
    except InvalidRequirement:
        return

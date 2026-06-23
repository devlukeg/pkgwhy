from __future__ import annotations

from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name


def read_requirements_dependencies(path: Path) -> set[str]:
    if not path.exists():
        return set()
    names: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return names
    for line in lines:
        cleaned = line.split("#", 1)[0].strip()
        if not cleaned or cleaned.startswith(
            ("-", "http:", "https:", "git+", "svn+", "hg+", "bzr+", "file://")
        ):
            continue
        try:
            names.add(canonicalize_name(Requirement(cleaned).name))
        except InvalidRequirement:
            continue
    return names

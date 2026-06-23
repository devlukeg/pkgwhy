from __future__ import annotations

from importlib.metadata import Distribution
from pathlib import Path

from pkgwhy.core.models import ReadabilityStatus, SourceAvailability
from pkgwhy.inspection.size import NATIVE_SUFFIXES


def distribution_file_paths(dist: Distribution | None, limit: int = 200) -> list[Path]:
    if dist is None or dist.files is None:
        return []
    paths: list[Path] = []
    for package_file in dist.files:
        try:
            path = Path(dist.locate_file(package_file))
        except (OSError, ValueError):
            continue
        try:
            if path.is_file():
                paths.append(path)
        except OSError:
            continue
        if len(paths) >= limit:
            break
    return paths


def infer_source_availability(paths: list[Path]) -> SourceAvailability:
    if not paths:
        return SourceAvailability.INSTALLED_METADATA_ONLY
    if any(path.suffix == ".py" for path in paths):
        return SourceAvailability.INSTALLED_SOURCE_PRESENT
    return SourceAvailability.SOURCE_AVAILABILITY_UNKNOWN


def infer_readability(paths: list[Path]) -> ReadabilityStatus:
    if any(path.suffix == ".py" for path in paths):
        return ReadabilityStatus.READABLE
    return ReadabilityStatus.NOT_ENOUGH_SOURCE_AVAILABLE


def detect_file_capabilities(paths: list[Path], entry_points: list[str]) -> list[str]:
    capabilities: set[str] = set()
    if entry_points:
        capabilities.add("CLI or plugin entrypoints declared in package metadata")
    if any(path.suffix.lower() in NATIVE_SUFFIXES for path in paths):
        capabilities.add("Native compiled code present")
    if any(path.suffix.lower() in {".js", ".mjs", ".cjs"} for path in paths):
        capabilities.add("Browser or JavaScript code present")
    if any(path.name in {"setup.py", "setup.cfg"} for path in paths):
        capabilities.add("Install-time setup files present")
    return sorted(capabilities)

from __future__ import annotations

import heapq
from importlib.metadata import Distribution
from pathlib import Path

from pkgwhy.core.models import LargestFile, PackageSize

NATIVE_SUFFIXES = {".so", ".pyd", ".dll", ".dylib", ".a", ".lib"}
JAVASCRIPT_SUFFIXES = {".js", ".mjs", ".cjs"}


def measure_distribution_size(dist: Distribution | None) -> PackageSize:
    if dist is None or dist.files is None:
        return PackageSize()

    total = 0
    python_bytes = 0
    native_binary_bytes = 0
    javascript_bytes = 0
    other_bytes = 0
    file_count = 0
    largest: list[LargestFile] = []

    for package_file in dist.files:
        try:
            path = Path(dist.locate_file(package_file))
        except (OSError, ValueError):
            continue
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        suffix = path.suffix.lower()
        total += size
        file_count += 1
        if suffix == ".py":
            python_bytes += size
        elif suffix in NATIVE_SUFFIXES:
            native_binary_bytes += size
        elif suffix in JAVASCRIPT_SUFFIXES:
            javascript_bytes += size
        else:
            other_bytes += size
        largest.append(LargestFile(path=str(package_file), size_bytes=size))

    largest = heapq.nlargest(5, largest, key=lambda item: item.size_bytes)
    return PackageSize(
        total_bytes=total,
        python_bytes=python_bytes,
        native_binary_bytes=native_binary_bytes,
        javascript_bytes=javascript_bytes,
        other_bytes=other_bytes,
        file_count=file_count,
        largest_files=largest,
    )

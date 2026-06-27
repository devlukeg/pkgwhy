from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

INTERNAL_PATHS = (
    "." + "agent/",
    "AGENTS" + ".md",
    "AGENT" + "_" + "WORK" + "_" + "ORDER" + ".md",
    "." + "co" + "dex/",
)
NORMALIZED_INTERNAL_PATHS = tuple(item.replace("\\", "/").lower() for item in INTERNAL_PATHS)
INTERNAL_DIR_NAMES = {item.strip("/") for item in NORMALIZED_INTERNAL_PATHS if item.endswith("/")}
INTERNAL_FILE_NAMES = {item.strip("/") for item in NORMALIZED_INTERNAL_PATHS if not item.endswith("/")}

INTERNAL_TEXT = (
    "Open" + "AI",
    "Chat" + "GPT",
    "Co" + "dex",
    "Code" + "Rabbit",
    "AGENTS" + ".md",
    "AGENT" + "_" + "WORK" + "_" + "ORDER",
    "AI" + " assistant",
    "generated" + " by",
    "model" + "-generated",
    "." + "co" + "dex",
)


def main() -> int:
    files = _tracked_files()
    failures: list[str] = []

    for name in files:
        if _is_internal_path(name):
            failures.append(f"internal path is tracked: {name}")

    for name in files:
        path = ROOT / name
        _scan_text_file(path, name, failures)

    for argument in sys.argv[1:]:
        artifact = (ROOT / argument).resolve()
        if not artifact.exists():
            failures.append(f"artifact path not found: {argument}")
            continue
        if artifact.is_dir():
            for path in artifact.rglob("*"):
                if path.is_file():
                    _scan_artifact_path(path, path.relative_to(ROOT).as_posix(), failures)
        else:
            _scan_artifact_path(artifact, artifact.relative_to(ROOT).as_posix(), failures)

    if failures:
        for failure in failures:
            print(failure)
        return 1

    print("public trace scan passed")
    return 0


def _scan_artifact_path(path: Path, label: str, failures: list[str]) -> None:
    if zipfile.is_zipfile(path):
        _scan_zip(path, label, failures)
        return
    if tarfile.is_tarfile(path):
        _scan_tar(path, label, failures)
        return
    _scan_text_file(path, label, failures)


def _scan_zip(path: Path, label: str, failures: list[str]) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                _scan_path_name(member.filename, f"{label}:{member.filename}", failures)
                try:
                    data = archive.read(member)
                except OSError:
                    continue
                _scan_bytes(data, f"{label}:{member.filename}", failures)
    except (OSError, zipfile.BadZipFile):
        failures.append(f"could not inspect artifact: {label}")


def _scan_tar(path: Path, label: str, failures: list[str]) -> None:
    try:
        with tarfile.open(path) as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                _scan_path_name(member.name, f"{label}:{member.name}", failures)
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                _scan_bytes(extracted.read(), f"{label}:{member.name}", failures)
    except (OSError, tarfile.TarError):
        failures.append(f"could not inspect artifact: {label}")


def _scan_text_file(path: Path, label: str, failures: list[str]) -> None:
    try:
        data = path.read_bytes()
    except OSError:
        return
    _scan_bytes(data, label, failures)


def _scan_bytes(data: bytes, label: str, failures: list[str]) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    lowered = text.lower()
    for pattern in INTERNAL_TEXT:
        if pattern.lower() in lowered:
            failures.append(f"internal trace text in {label}: {pattern}")


def _scan_path_name(name: str, label: str, failures: list[str]) -> None:
    if _is_internal_path(name):
        failures.append(f"internal path in artifact: {label}")


def _is_internal_path(name: str) -> bool:
    normalized = name.replace("\\", "/").lower().strip("/")
    parts = [part for part in normalized.split("/") if part and part != "."]
    if not parts:
        return False
    return parts[-1] in INTERNAL_FILE_NAMES or any(part in INTERNAL_DIR_NAMES for part in parts)


def _tracked_files() -> list[str]:
    completed = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in completed.stdout.splitlines() if line]


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

INTERNAL_PATHS = (
    "." + "agent/",
    "AGENTS" + ".md",
    "AGENT" + "_" + "WORK" + "_" + "ORDER" + ".md",
    "." + "codex/",
)

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
    "." + "codex",
)


def main() -> int:
    files = _tracked_files()
    failures: list[str] = []

    for name in files:
        normalized = name.replace("\\", "/")
        if any(normalized == item.rstrip("/") or normalized.startswith(item) for item in INTERNAL_PATHS):
            failures.append(f"internal path is tracked: {name}")

    for name in files:
        path = ROOT / name
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for pattern in INTERNAL_TEXT:
            if pattern in text:
                failures.append(f"internal trace text in {name}: {pattern}")

    if failures:
        for failure in failures:
            print(failure)
        return 1

    print("public trace scan passed")
    return 0


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

from pathlib import Path

from pkgwhy.manifests.pyproject import read_pyproject_dependencies
from pkgwhy.manifests.lockfiles import (
    read_lockfile_dependencies,
    read_poetry_lock_dependencies,
    read_uv_lock_dependencies,
)
from pkgwhy.manifests.requirements import read_requirements_dependencies


def test_read_pyproject_dependencies_includes_optional_groups(tmp_path: Path) -> None:
    path = tmp_path / "pyproject.toml"
    path.write_text(
        """
[project]
dependencies = ["Typer>=0.12"]

[project.optional-dependencies]
dev = ["pytest>=8"]
""",
        encoding="utf-8",
    )

    assert read_pyproject_dependencies(path) == {"typer", "pytest"}


def test_read_pyproject_dependencies_ignores_malformed_optional_group(tmp_path: Path) -> None:
    path = tmp_path / "pyproject.toml"
    path.write_text(
        """
[project]
dependencies = ["Typer>=0.12"]

[project.optional-dependencies]
dev = "pytest>=8"
""",
        encoding="utf-8",
    )

    assert read_pyproject_dependencies(path) == {"typer"}


def test_read_requirements_dependencies_ignores_comments_and_options(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text("rich>=13\n# comment\n-r other.txt\n", encoding="utf-8")

    assert read_requirements_dependencies(path) == {"rich"}


def test_read_uv_lock_dependencies_reads_package_names(tmp_path: Path) -> None:
    path = tmp_path / "uv.lock"
    path.write_text(
        """
[[package]]
name = "Typer"
version = "0.1.0"

[[package]]
name = "Rich"
version = "0.1.0"
""",
        encoding="utf-8",
    )

    assert read_uv_lock_dependencies(path) == {"typer", "rich"}


def test_read_poetry_lock_dependencies_reads_package_names(tmp_path: Path) -> None:
    path = tmp_path / "poetry.lock"
    path.write_text(
        """
[[package]]
name = "Requests"
version = "0.1.0"
""",
        encoding="utf-8",
    )

    assert read_poetry_lock_dependencies(path) == {"requests"}


def test_read_lockfile_dependencies_combines_supported_lockfiles(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        """
[[package]]
name = "Typer"
version = "0.1.0"
""",
        encoding="utf-8",
    )
    (tmp_path / "poetry.lock").write_text(
        """
[[package]]
name = "Requests"
version = "0.1.0"
""",
        encoding="utf-8",
    )

    assert read_lockfile_dependencies(tmp_path) == {
        "uv.lock": {"typer"},
        "poetry.lock": {"requests"},
    }

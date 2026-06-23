from pathlib import Path

from pkgwhy.manifests.pyproject import read_pyproject_dependencies
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

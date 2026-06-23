from pathlib import Path

from pkgwhy.dependencies.graph import transitive_dependencies_for, transitive_parents_for
from pkgwhy.dependencies.reason import explain_dependency_reason


def test_transitive_dependencies_for_walks_installed_style_graph() -> None:
    graph = {
        "app": {"rich", "typer"},
        "typer": {"click", "typing-extensions"},
        "click": {"colorama"},
        "rich": set(),
        "typing-extensions": set(),
        "colorama": set(),
    }

    assert transitive_dependencies_for({"app"}, graph) == {
        "rich",
        "typer",
        "click",
        "typing-extensions",
        "colorama",
    }


def test_transitive_dependencies_excludes_direct_dependencies_from_result() -> None:
    graph = {
        "app": {"typer"},
        "typer": {"rich"},
        "rich": set(),
    }

    assert transitive_dependencies_for({"app", "typer"}, graph) == {"rich"}


def test_transitive_parents_for_reports_immediate_parent_signal() -> None:
    graph = {
        "app": {"typer"},
        "typer": {"click"},
        "click": {"colorama"},
        "colorama": set(),
    }

    assert transitive_parents_for("click", {"app"}, graph) == {"typer"}


def test_explain_dependency_reason_reports_direct_lockfile_and_import_signals(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
dependencies = ["Typer>=0.12"]
""",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        """
[[package]]
name = "typer"
version = "0.1.0"
""",
        encoding="utf-8",
    )
    package_dir = tmp_path / "src"
    package_dir.mkdir()
    (package_dir / "app.py").write_text("import typer\n", encoding="utf-8")

    reason = explain_dependency_reason("typer", tmp_path, metadata=None)

    assert reason.status == "direct"
    assert reason.declared_in == ["pyproject.toml"]
    assert reason.lockfiles == ["uv.lock"]
    assert reason.imported_by_project is True
    assert any("declared in pyproject.toml" in item for item in reason.evidence)

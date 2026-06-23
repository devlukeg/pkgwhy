from pkgwhy.dependencies.graph import transitive_dependencies_for


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

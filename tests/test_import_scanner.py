from pathlib import Path

from pkgwhy.imports.scanner import scan_project_imports


def test_scan_project_imports_reads_ast_without_importing(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("import json\nfrom pathlib import Path\nfrom pkgwhy.cli import app\n", encoding="utf-8")

    assert scan_project_imports(tmp_path) == {"json", "pathlib", "pkgwhy"}


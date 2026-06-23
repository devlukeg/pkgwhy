import json
from pathlib import Path

import pytest

from pkgwhy.registry.local import REGISTRY_INDEX_FILENAME, init_local_registry, load_registry_index
from pkgwhy.registry.publish import publish_local_tool


def test_publish_single_python_script_creates_bundle_and_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    registry_path = tmp_path / "registry"
    init_local_registry(registry_path)
    script = tmp_path / "hello_tool.py"
    script.write_text("print('hello')\n", encoding="utf-8")

    result = publish_local_tool(script)

    assert result.manifest.name == "hello_tool"
    assert result.manifest.owner == "local"
    assert result.bundle_path.exists()
    assert len(result.sha256) == 64
    assert result.manifest_path.exists()
    index = load_registry_index(registry_path)
    assert len(index.tools) == 1
    assert index.tools[0].name == "hello_tool"
    assert index.tools[0].sha256 == result.sha256
    assert (registry_path / REGISTRY_INDEX_FILENAME).exists()


def test_publish_folder_manifest_creates_manifest_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    registry_path = tmp_path / "registry"
    init_local_registry(registry_path)
    tool_dir = tmp_path / "tool"
    tool_dir.mkdir()
    (tool_dir / "pkgwhy.toml").write_text(
        """
[tool]
name = "folder-tool"
owner = "luke"
version = "0.2.0"
description = "Folder tool"
artifact_type = "folder"
entrypoint = "main.py"
declared_permissions = ["filesystem_read"]

[security]
signing_status = "not_implemented"

[agent]
default_decision = "review_manually"
non_interactive_decision = "block"
""",
        encoding="utf-8",
    )
    (tool_dir / "main.py").write_text("print('folder')\n", encoding="utf-8")

    result = publish_local_tool(tool_dir)

    manifest_data = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert result.manifest.name == "folder-tool"
    assert result.bundle_path.exists()
    assert manifest_data["security"]["signing_status"] == "not_implemented"
    index = load_registry_index(registry_path)
    assert index.tools[0].owner == "luke"
    assert index.tools[0].artifact_type == "folder"


def test_publish_requires_current_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    script = tmp_path / "hello.py"
    script.write_text("print('hello')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="No current registry"):
        publish_local_tool(script)

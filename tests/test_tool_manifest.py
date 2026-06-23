from pathlib import Path

import pytest

from pkgwhy.core.models import AgentDecision, ToolArtifactType
from pkgwhy.registry.manifest import read_tool_manifest


def test_read_tool_manifest_validates_complete_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "pkgwhy.toml"
    manifest_path.write_text(
        """
[tool]
name = "demo-tool"
owner = "luke"
version = "0.1.0"
description = "Demo private tool"
artifact_type = "script"
entrypoint = "demo.py"
python_requires = ">=3.11"
dependencies = ["typer>=0.12"]
declared_permissions = ["filesystem_read"]

[security]
requires_human_approval = true
allow_unsigned = false
allow_unpinned_dependencies = false
signing_status = "not_implemented"

[agent]
default_decision = "review_manually"
non_interactive_decision = "block"
""",
        encoding="utf-8",
    )

    manifest = read_tool_manifest(tmp_path)

    assert manifest.schema_version == "pkgwhy.tool_manifest.v1"
    assert manifest.name == "demo-tool"
    assert manifest.owner == "luke"
    assert manifest.artifact_type == ToolArtifactType.SCRIPT
    assert manifest.entrypoint == "demo.py"
    assert manifest.dependencies == ["typer>=0.12"]
    assert manifest.declared_permissions == ["filesystem_read"]
    assert manifest.security.signing_status == "not_implemented"
    assert manifest.agent.non_interactive_decision == AgentDecision.BLOCK


def test_read_tool_manifest_rejects_missing_tool_table(tmp_path: Path) -> None:
    manifest_path = tmp_path / "pkgwhy.toml"
    manifest_path.write_text("[security]\nrequires_human_approval = true\n", encoding="utf-8")

    with pytest.raises(ValueError, match=r"\[tool\]"):
        read_tool_manifest(manifest_path)


def test_read_tool_manifest_rejects_fake_signing_status(tmp_path: Path) -> None:
    manifest_path = tmp_path / "pkgwhy.toml"
    manifest_path.write_text(
        """
[tool]
name = "demo-tool"
owner = "luke"
version = "0.1.0"
description = "Demo private tool"
artifact_type = "script"
entrypoint = "demo.py"

[security]
signing_status = "verified"
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="not_implemented"):
        read_tool_manifest(manifest_path)


def test_read_tool_manifest_rejects_invalid_artifact_type(tmp_path: Path) -> None:
    manifest_path = tmp_path / "pkgwhy.toml"
    manifest_path.write_text(
        """
[tool]
name = "demo-tool"
owner = "luke"
version = "0.1.0"
description = "Demo private tool"
artifact_type = "container"
entrypoint = "demo.py"
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        read_tool_manifest(manifest_path)


def test_read_tool_manifest_rejects_trailing_identifier_punctuation(tmp_path: Path) -> None:
    manifest_path = tmp_path / "pkgwhy.toml"
    manifest_path.write_text(
        """
[tool]
name = "demo-"
owner = "luke"
version = "0.1.0"
description = "Demo private tool"
artifact_type = "script"
entrypoint = "demo.py"
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="start and end"):
        read_tool_manifest(manifest_path)

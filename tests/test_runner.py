import json
import hashlib
import io
import tarfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pkgwhy.cli import app
from pkgwhy.core.models import ToolTrustState
from pkgwhy.registry.local import init_local_registry, load_registry_index, save_registry_index
from pkgwhy.registry.publish import publish_local_tool
from pkgwhy.registry.run import RUNNER_ISOLATION_WARNING, run_local_tool
from pkgwhy.registry.trust import set_tool_trust_state

runner = CliRunner()


def test_run_local_tool_executes_controlled_script_and_logs_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    registry_path = tmp_path / "registry"
    init_local_registry(registry_path)
    script = tmp_path / "hello_runner.py"
    script.write_text("print('hello from runner')\n", encoding="utf-8")
    publish_local_tool(script)

    result = run_local_tool("local/hello_runner")

    assert result.exit_code == 0
    assert result.status == "completed"
    assert result.stdout == "hello from runner\n"
    assert result.stderr == ""
    assert result.warning == RUNNER_ISOLATION_WARNING
    assert result.log_path.exists()
    assert (registry_path / "venvs" / "local" / "hello_runner" / "0.1.0").exists()
    log_data = json.loads(result.log_path.read_text(encoding="utf-8"))
    assert log_data["schema_version"] == "pkgwhy.tool_run.v1"
    assert log_data["tool"] == "local/hello_runner"
    assert log_data["exit_code"] == 0
    assert log_data["warning"] == RUNNER_ISOLATION_WARNING
    assert log_data["policy_decision"] == "review_manually"
    assert log_data["policy_reasons"] == []
    assert any(
        "signature verification is not implemented" in warning.lower()
        for warning in log_data["policy_warnings"]
    )


def test_run_cli_prints_warning_output_and_log_path(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    registry_path = tmp_path / "registry"
    script = tmp_path / "cli_runner_tool.py"
    script.write_text("print('cli runner ok')\n", encoding="utf-8")

    assert runner.invoke(app, ["registry", "init", str(registry_path)], env=env).exit_code == 0
    assert runner.invoke(app, ["publish", str(script)], env=env).exit_code == 0
    result = runner.invoke(app, ["run", "local/cli_runner_tool"], env=env)

    assert result.exit_code == 0
    assert RUNNER_ISOLATION_WARNING in result.stderr
    assert "cli runner ok" in result.output
    assert "Execution log:" in result.output


def test_run_cli_non_interactive_blocks_default_tool(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    registry_path = tmp_path / "registry"
    script = tmp_path / "noninteractive_cli_tool.py"
    script.write_text("print('should not run')\n", encoding="utf-8")

    assert runner.invoke(app, ["registry", "init", str(registry_path)], env=env).exit_code == 0
    assert runner.invoke(app, ["publish", str(script)], env=env).exit_code == 0
    result = runner.invoke(app, ["run", "local/noninteractive_cli_tool", "--non-interactive"], env=env)

    assert result.exit_code == 1
    assert RUNNER_ISOLATION_WARNING in result.stderr
    assert "Tool policy blocks execution" in result.output
    assert "should not run" not in result.output


def test_run_local_tool_blocks_hash_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    registry_path = tmp_path / "registry"
    init_local_registry(registry_path)
    script = tmp_path / "tampered_runner.py"
    script.write_text("print('should not run')\n", encoding="utf-8")
    publish_local_tool(script)
    index = load_registry_index(registry_path)
    index.tools[0].sha256 = "0" * 64
    save_registry_index(registry_path, index)

    with pytest.raises(ValueError, match="hash is not verified"):
        run_local_tool("local/tampered_runner")


def test_run_local_tool_blocks_quarantined_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    init_local_registry(tmp_path / "registry")
    script = tmp_path / "quarantined_runner.py"
    script.write_text("print('should not run')\n", encoding="utf-8")
    publish_local_tool(script)
    set_tool_trust_state("local/quarantined_runner", ToolTrustState.QUARANTINED)

    with pytest.raises(ValueError, match="trust state blocks execution"):
        run_local_tool("local/quarantined_runner")


def test_run_local_tool_rejects_missing_registry_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    init_local_registry(tmp_path / "registry")

    with pytest.raises(ValueError, match="not published"):
        run_local_tool("local/missing_runner")


def test_run_local_tool_rejects_unsupported_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    init_local_registry(tmp_path / "registry")
    tool_dir = tmp_path / "shell-tool"
    tool_dir.mkdir()
    (tool_dir / "pkgwhy.toml").write_text(
        """
[tool]
name = "shell-tool"
owner = "local"
version = "0.1.0"
description = "Unsupported shell entrypoint"
artifact_type = "folder"
entrypoint = "run.sh"

[security]
signing_status = "not_implemented"

[agent]
default_decision = "review_manually"
non_interactive_decision = "block"
""",
        encoding="utf-8",
    )
    (tool_dir / "run.sh").write_text("echo no\n", encoding="utf-8")
    publish_local_tool(tool_dir)

    with pytest.raises(ValueError, match="Unsupported entrypoint"):
        run_local_tool("local/shell-tool")


def test_run_local_tool_defers_dependency_installation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    registry_path = tmp_path / "registry"
    init_local_registry(registry_path)
    tool_dir = tmp_path / "dependency-tool"
    tool_dir.mkdir()
    (tool_dir / "pkgwhy.toml").write_text(
        """
[tool]
name = "dependency-tool"
owner = "local"
version = "0.1.0"
description = "Tool with deferred dependencies"
artifact_type = "folder"
entrypoint = "main.py"
dependencies = ["requests==2.32.0"]

[security]
signing_status = "not_implemented"

[agent]
default_decision = "review_manually"
non_interactive_decision = "block"
""",
        encoding="utf-8",
    )
    (tool_dir / "main.py").write_text("print('should not install deps')\n", encoding="utf-8")
    publish_local_tool(tool_dir)

    with pytest.raises(ValueError, match="Dependency installation is not implemented"):
        run_local_tool("local/dependency-tool")


def test_run_local_tool_rejects_path_traversal_in_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    registry_path = tmp_path / "registry"
    init_local_registry(registry_path)
    script = tmp_path / "traversal_runner.py"
    script.write_text("print('should not extract')\n", encoding="utf-8")
    publish_local_tool(script)
    index = load_registry_index(registry_path)
    bundle_path = registry_path / index.tools[0].bundle_path
    payload = b"print('unsafe')\n"
    with tarfile.open(bundle_path, "w:gz") as archive:
        member = tarfile.TarInfo("../../../evil.py")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    index.tools[0].sha256 = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    save_registry_index(registry_path, index)

    with pytest.raises(ValueError, match="Unsafe path"):
        run_local_tool("local/traversal_runner")

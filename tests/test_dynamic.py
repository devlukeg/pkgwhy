import pytest
from pydantic import ValidationError

from pkgwhy.core.models import DynamicAnalysisResult, DynamicFilesystemEvent
from pkgwhy.dynamic.analysis import build_unavailable_dynamic_result, run_controlled_fixture


def test_unavailable_dynamic_result_blocks_without_events(monkeypatch) -> None:
    monkeypatch.setattr("pkgwhy.dynamic.analysis.shutil.which", lambda _: None)

    result = build_unavailable_dynamic_result("demo-target", container=True, network="off")

    assert result.schema_version == "pkgwhy.dynamic_analysis.v1"
    assert result.target == "demo-target"
    assert result.mode == "inspect"
    assert result.sandbox_backend == "container"
    assert result.network_mode == "off"
    assert result.filesystem_mode == "scratch"
    assert result.status == "backend_unavailable"
    assert result.decision == "block"
    assert result.process_events == []
    assert result.filesystem_events == []
    assert result.network_events == []
    assert any("Empty event lists are not proof" in limitation for limitation in result.limitations)
    assert any("Docker container backend is unavailable" in warning for warning in result.warnings)


def test_unavailable_dynamic_result_detects_docker_without_invoking_it(monkeypatch) -> None:
    monkeypatch.setattr("pkgwhy.dynamic.analysis.shutil.which", lambda _: "/usr/bin/docker")

    result = build_unavailable_dynamic_result("demo-target", container=True, network="off")

    assert result.status == "backend_unavailable"
    assert any("Docker executable was detected" in warning for warning in result.warnings)
    assert any("does not invoke Docker" in limitation for limitation in result.limitations)


def test_dynamic_result_model_accepts_observed_events_when_backend_supplies_them() -> None:
    result = DynamicAnalysisResult(
        target="fixture",
        sandbox_backend="controlled_fixture",
        status="completed",
        decision="allow_with_caution",
        filesystem_events=[DynamicFilesystemEvent(path="/scratch/output.txt", action="created")],
    )

    assert result.filesystem_events[0].path == "/scratch/output.txt"


def test_dynamic_result_rejects_unknown_network_mode() -> None:
    with pytest.raises(ValidationError):
        DynamicAnalysisResult(
            target="fixture",
            sandbox_backend="container",
            network_mode="on",
            status="blocked",
            decision="block",
        )


def test_controlled_fixture_execution_records_scratch_events_without_host_env(tmp_path, monkeypatch) -> None:
    fixture_root = tmp_path / "fixtures"
    scratch_dir = tmp_path / "scratch"
    fixture_root.mkdir()
    fixture = fixture_root / "write_output.py"
    fixture.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "Path('output.txt').write_text(os.environ.get('PKGWHY_SHOULD_NOT_LEAK', 'missing'), encoding='utf-8')\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PKGWHY_SHOULD_NOT_LEAK", "secret-host-value")

    result = run_controlled_fixture(fixture, fixture_root=fixture_root, scratch_dir=scratch_dir)

    assert result.status == "completed"
    assert result.decision == "allow_with_caution"
    assert result.sandbox_backend == "controlled_fixture"
    assert result.process_events[0].exit_code == 0
    assert result.filesystem_events == [DynamicFilesystemEvent(path="output.txt", action="created")]
    assert result.network_events == []
    assert (scratch_dir / "output.txt").read_text(encoding="utf-8") == "missing"


def test_controlled_fixture_refuses_paths_outside_fixture_root(tmp_path) -> None:
    fixture_root = tmp_path / "fixtures"
    scratch_dir = tmp_path / "scratch"
    fixture_root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("print('outside')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="fixture_root"):
        run_controlled_fixture(outside, fixture_root=fixture_root, scratch_dir=scratch_dir)

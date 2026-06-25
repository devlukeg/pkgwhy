import pytest
from pydantic import ValidationError

from pkgwhy.core.models import DynamicAnalysisResult, DynamicFilesystemEvent
from pkgwhy.dynamic.analysis import build_unavailable_dynamic_result


def test_unavailable_dynamic_result_blocks_without_events() -> None:
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


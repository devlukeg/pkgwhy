from pathlib import Path

from pkgwhy.inspection.python_static import analyze_python_files


def test_analyze_python_files_detects_capability_signals_without_importing(tmp_path: Path) -> None:
    source = tmp_path / "fixture.py"
    source.write_text(
        """
import os
import subprocess
import requests
import pickle

API_KEY_NAME = "SERVICE_API_KEY"

def run(payload):
    token = os.environ.get(API_KEY_NAME)
    subprocess.run(["echo", token])
    requests.get("https://example.invalid")
    return pickle.loads(payload)
""",
        encoding="utf-8",
    )

    analysis = analyze_python_files([source])

    assert analysis.files_scanned == 1
    assert "Environment variable access signals" in analysis.detected_capabilities
    assert "Subprocess or shell execution signals" in analysis.detected_capabilities
    assert "Network access signals" in analysis.detected_capabilities
    assert "Deserialisation risk signals" in analysis.detected_capabilities
    assert "Credential or token access patterns" in analysis.detected_capabilities


def test_analyze_python_files_reports_parse_warning(tmp_path: Path) -> None:
    source = tmp_path / "broken.py"
    source.write_text("def broken(:\n", encoding="utf-8")

    analysis = analyze_python_files([source])

    assert analysis.files_scanned == 0
    assert any("Could not statically parse Python file" in warning for warning in analysis.warnings)

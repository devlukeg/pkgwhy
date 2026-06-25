from pathlib import Path
from textwrap import dedent

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


def test_analyze_python_files_emits_rule_evidence_with_lines_and_symbols(tmp_path: Path) -> None:
    source = tmp_path / "signals.py"
    source.write_text(
        dedent(
            """
            import base64
            import importlib
            import marshal
            import os
            import subprocess
            import yaml
            import zlib

            def run(payload):
                eval("1")
                exec("x = 1")
                compile("x = 1", "<x>", "exec")
                __import__("json")
                importlib.import_module("json")
                marshal.loads(payload)
                yaml.load(payload)
                base64.b64decode(payload)
                zlib.decompress(payload)
                os.environ.get("SERVICE_TOKEN")
                subprocess.run(["python", "-m", "pip", "install", "demo"])
            """
        ),
        encoding="utf-8",
    )

    analysis = analyze_python_files([source])
    rule_by_symbol = {item.symbol: item for item in analysis.rule_evidence}

    assert rule_by_symbol["eval"].rule_id == "PKGWHY-PY-001"
    assert rule_by_symbol["exec"].rule_id == "PKGWHY-PY-001"
    assert rule_by_symbol["compile"].rule_id == "PKGWHY-PY-001"
    assert rule_by_symbol["__import__"].rule_id == "PKGWHY-PY-002"
    assert rule_by_symbol["importlib.import_module"].rule_id == "PKGWHY-PY-002"
    assert rule_by_symbol["marshal.loads"].rule_id == "PKGWHY-PY-003"
    assert rule_by_symbol["yaml.load"].rule_id == "PKGWHY-PY-008"
    assert rule_by_symbol["base64.b64decode"].rule_id == "PKGWHY-PY-004"
    assert rule_by_symbol["zlib.decompress"].rule_id == "PKGWHY-PY-004"
    assert any(item.symbol == "subprocess.run" and item.rule_id == "PKGWHY-PY-005" for item in analysis.rule_evidence)
    assert any(item.rule_id == "PKGWHY-PY-006" for item in analysis.rule_evidence)
    assert any(item.rule_id == "PKGWHY-PY-007" for item in analysis.rule_evidence)
    assert all(item.file_path == "signals.py" for item in analysis.rule_evidence)
    assert all(item.line_number is not None and item.line_number >= 1 for item in analysis.rule_evidence)


def test_analyze_python_files_reports_parse_warning(tmp_path: Path) -> None:
    source = tmp_path / "broken.py"
    source.write_text("def broken(:\n", encoding="utf-8")

    analysis = analyze_python_files([source])

    assert analysis.files_scanned == 0
    assert any("Could not statically parse Python file" in warning for warning in analysis.warnings)


def test_analyze_python_files_reports_encoded_literals_and_obfuscation_bootstrap(tmp_path: Path) -> None:
    source = tmp_path / "encoded.py"
    encoded = "A" * 140
    source.write_text(
        dedent(
            f"""
            payload = "{encoded}"
            __pyarmor__ = "bootstrap"
            marker = "pytransform"
            """
        ),
        encoding="utf-8",
    )

    analysis = analyze_python_files([source])

    assert "Encoded payload handling signals" in analysis.detected_capabilities
    assert "Python obfuscation signals" in analysis.detected_capabilities
    assert any(rule.rule_id == "PKGWHY-PY-004" and rule.symbol == "large encoded-looking string literal" for rule in analysis.rule_evidence)
    assert any(rule.rule_id == "PKGWHY-PY-009" for rule in analysis.rule_evidence)
    assert encoded not in " ".join(analysis.evidence)

from pathlib import Path

from pkgwhy.core.models import ReadabilityStatus
from pkgwhy.inspection.files import analyze_file_signals, infer_readability


def test_analyze_file_signals_detects_javascript_minification_and_dynamic_patterns(tmp_path: Path) -> None:
    script = tmp_path / "bundle.min.js"
    script.write_text("var _0xabc='x';eval(atob(_0xabc));" + ("a" * 1_100), encoding="utf-8")

    analysis = analyze_file_signals([script], entry_points=[])

    assert analysis.javascript_files_scanned == 1
    assert "Browser or JavaScript code present" in analysis.detected_capabilities
    assert "JavaScript dynamic code execution signals" in analysis.detected_capabilities
    assert "Encoded payload handling signals" in analysis.detected_capabilities
    assert any("appears minified" in warning for warning in analysis.warnings)
    assert infer_readability([script], analysis) == ReadabilityStatus.MINIFIED


def test_analyze_file_signals_detects_binary_wasm_shell_and_setup_files(tmp_path: Path) -> None:
    native = tmp_path / "extension.so"
    wasm = tmp_path / "module.wasm"
    shell = tmp_path / "install.sh"
    setup = tmp_path / "setup.py"
    for path in [native, wasm, shell, setup]:
        path.write_bytes(b"")
    shell.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    setup.write_text("from setuptools import setup\n", encoding="utf-8")

    analysis = analyze_file_signals([native, wasm, shell, setup], entry_points=["pkgwhy = pkgwhy.cli:app"])

    assert "Native compiled code present" in analysis.detected_capabilities
    assert "WASM binary code present" in analysis.detected_capabilities
    assert "Shell script files present" in analysis.detected_capabilities
    assert "Install-time setup files present" in analysis.detected_capabilities
    assert "CLI or plugin entrypoints declared in package metadata" in analysis.detected_capabilities
    assert analysis.native_binaries_detected == 1
    assert analysis.wasm_files_detected == 1
    assert analysis.shell_scripts_detected == 1
    assert analysis.setup_files_detected == 1


def test_analyze_file_signals_detects_shell_shebang_without_shell_suffix(tmp_path: Path) -> None:
    script = tmp_path / "postinstall"
    script.write_text("#!/usr/bin/env bash\necho ok\n", encoding="utf-8")

    analysis = analyze_file_signals([script], entry_points=[])

    assert "Shell script files present" in analysis.detected_capabilities
    assert analysis.shell_scripts_detected == 1


def test_analyze_file_signals_escalates_heavy_javascript_obfuscation(tmp_path: Path) -> None:
    script = tmp_path / "obfuscated.js"
    script.write_text("var _0xabc='\\x41';while(!![]){debugger;break;}", encoding="utf-8")

    analysis = analyze_file_signals([script], entry_points=[])

    assert "JavaScript obfuscation signals" in analysis.detected_capabilities
    assert any("likely obfuscated javascript" in warning.lower() for warning in analysis.warnings)
    assert infer_readability([script], analysis) == ReadabilityStatus.LIKELY_OBFUSCATED


def test_analyze_file_signals_avoids_javascript_call_substring_false_positives(tmp_path: Path) -> None:
    script = tmp_path / "helpers.js"
    script.write_text("function retrieval(){} function getFunction(){} const catob = 1;", encoding="utf-8")

    analysis = analyze_file_signals([script], entry_points=[])

    assert "JavaScript dynamic code execution signals" not in analysis.detected_capabilities
    assert "Encoded payload handling signals" not in analysis.detected_capabilities

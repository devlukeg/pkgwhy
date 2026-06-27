from pathlib import Path

from pkgwhy.inspection.files import analyze_file_signals
from pkgwhy.inspection.python_static import analyze_python_files

CORPUS_ROOT = Path(__file__).parent / "fixtures" / "static_rule_corpus"
PYTHON_CORPUS = CORPUS_ROOT / "python"
ASSET_CORPUS = CORPUS_ROOT / "assets"


def _python_fixture(name: str) -> Path:
    return PYTHON_CORPUS / name


def _asset_fixture(name: str) -> Path:
    return ASSET_CORPUS / name


def test_python_static_corpus_emits_expected_rule_ids_and_locations() -> None:
    paths = [
        _python_fixture("dynamic_execution.py"),
        _python_fixture("deserialisation.py"),
        _python_fixture("encoded_payloads.py"),
        _python_fixture("process_environment_package_manager.py"),
    ]

    analysis = analyze_python_files(paths)
    rules = {(rule.rule_id, rule.file_path, rule.line_number, rule.symbol) for rule in analysis.rule_evidence}

    assert rules == {
        ("PKGWHY-PY-001", "dynamic_execution.py", 5, "eval"),
        ("PKGWHY-PY-001", "dynamic_execution.py", 6, "exec"),
        ("PKGWHY-PY-001", "dynamic_execution.py", 7, "compile"),
        ("PKGWHY-PY-002", "dynamic_execution.py", 8, "__import__"),
        ("PKGWHY-PY-002", "dynamic_execution.py", 9, "importlib.import_module"),
        ("PKGWHY-PY-003", "deserialisation.py", 7, "pickle.loads"),
        ("PKGWHY-PY-003", "deserialisation.py", 8, "marshal.loads"),
        ("PKGWHY-PY-008", "deserialisation.py", 9, "yaml.load"),
        ("PKGWHY-PY-004", "encoded_payloads.py", 4, "large encoded-looking string literal"),
        ("PKGWHY-PY-004", "encoded_payloads.py", 8, "base64.b64decode"),
        ("PKGWHY-PY-004", "encoded_payloads.py", 9, "zlib.decompress"),
        ("PKGWHY-PY-009", "encoded_payloads.py", 10, "__pyarmor__"),
        ("PKGWHY-PY-005", "process_environment_package_manager.py", 7, "subprocess.run"),
        ("PKGWHY-PY-006", "process_environment_package_manager.py", 6, "os.environ"),
        ("PKGWHY-PY-006", "process_environment_package_manager.py", 6, "credential-like string literal"),
        ("PKGWHY-PY-007", "process_environment_package_manager.py", 7, "subprocess.run"),
    }
    assert analysis.files_scanned == len(paths)


def test_python_text_corpus_masks_credentials_and_sanitizes_urls() -> None:
    source = _python_fixture("url_credential_patterns.py")

    analysis = analyze_file_signals([source], entry_points=[])
    rules = {(rule.rule_id, rule.file_path, rule.line_number, rule.symbol) for rule in analysis.rule_evidence}
    combined_output = " ".join(
        analysis.evidence
        + analysis.credential_references
        + analysis.url_references
        + [item.message for item in analysis.rule_evidence]
        + [text for item in analysis.rule_evidence for text in item.evidence]
    )

    assert rules == {
        ("PKGWHY-CRED-001", "url_credential_patterns.py", 1, "SERVICE_API_TOKEN"),
        ("PKGWHY-NET-001", "url_credential_patterns.py", 2, "example.invalid"),
    }
    assert analysis.url_references == ["https://example.invalid/..."]
    assert analysis.domain_references == ["example.invalid"]
    assert "placeholdertoken123" not in combined_output
    assert "user:password" not in combined_output
    assert "token=placeholder" not in combined_output


def test_javascript_corpus_emits_rule_ids_and_false_positive_controls() -> None:
    signal_file = _asset_fixture("javascript_signals.min.js")
    false_positive_file = _asset_fixture("javascript_false_positive.js")

    analysis = analyze_file_signals([signal_file, false_positive_file], entry_points=[])
    rules = {(rule.rule_id, rule.file_path, rule.line_number, rule.symbol) for rule in analysis.rule_evidence}
    false_positive_rules = [rule for rule in analysis.rule_evidence if rule.file_path == false_positive_file.name]

    assert rules == {
        ("PKGWHY-JS-001", "javascript_signals.min.js", 1, "minified-javascript"),
        ("PKGWHY-JS-002", "javascript_signals.min.js", 1, "JavaScript eval call"),
        ("PKGWHY-JS-003", "javascript_signals.min.js", 1, "JavaScript base64 decode call"),
        ("PKGWHY-JS-003", "javascript_signals.min.js", 1, "large encoded-looking string"),
        ("PKGWHY-JS-004", "javascript_signals.min.js", 1, "javascript-obfuscation"),
        ("PKGWHY-JS-005", "javascript_signals.min.js", 1, "sourceMappingURL"),
    }
    assert analysis.javascript_files_scanned == 2
    assert not any(rule.rule_id in {"PKGWHY-JS-002", "PKGWHY-JS-003"} for rule in false_positive_rules)


def test_native_shell_and_build_file_corpus_emits_expected_rules() -> None:
    paths = [
        _asset_fixture("extension.so"),
        _asset_fixture("helper.exe"),
        _asset_fixture("module.wasm"),
        _asset_fixture("postinstall"),
        _asset_fixture("setup.py"),
        _asset_fixture("pyproject.toml"),
        _asset_fixture("setup.cfg"),
    ]

    analysis = analyze_file_signals(paths, entry_points=[])
    rules = {(rule.rule_id, rule.file_path, rule.line_number, rule.symbol) for rule in analysis.rule_evidence}

    assert rules == {
        ("PKGWHY-BIN-001", "extension.so", None, ".so"),
        ("PKGWHY-BIN-002", "module.wasm", None, ".wasm"),
        ("PKGWHY-BIN-003", "helper.exe", None, ".exe"),
        ("PKGWHY-BUILD-001", "setup.py", None, "setup.py"),
        ("PKGWHY-BUILD-002", "setup.py", 1, "subprocess or shell reference"),
        ("PKGWHY-BUILD-003", "setup.py", 2, "network access reference"),
        ("PKGWHY-BUILD-004", "setup.py", 7, "dynamic execution reference"),
        ("PKGWHY-BUILD-005", "pyproject.toml", 3, "hatchling.build"),
        ("PKGWHY-BUILD-006", "setup.cfg", None, "setup.cfg"),
        ("PKGWHY-NET-001", "setup.py", 6, "example.invalid"),
    }
    assert analysis.native_binaries_detected == 2
    assert analysis.wasm_files_detected == 1
    assert analysis.shell_scripts_detected == 1
    assert analysis.setup_files_detected == 1

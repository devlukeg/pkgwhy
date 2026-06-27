from pathlib import Path

from pkgwhy.inspection.files import analyze_file_signals
from pkgwhy.inspection.python_static import analyze_python_files

CORPUS_ROOT = Path(__file__).parent / "fixtures" / "static_rule_corpus"
PYTHON_CORPUS = CORPUS_ROOT / "python"


def _python_fixture(name: str) -> Path:
    return PYTHON_CORPUS / name


def test_python_static_corpus_emits_expected_rule_ids_and_locations() -> None:
    paths = [
        _python_fixture("dynamic_execution.py"),
        _python_fixture("deserialisation.py"),
        _python_fixture("encoded_payloads.py"),
        _python_fixture("process_environment_package_manager.py"),
    ]

    analysis = analyze_python_files(paths)
    rules = {(rule.rule_id, rule.file_path, rule.line_number, rule.symbol) for rule in analysis.rule_evidence}

    assert ("PKGWHY-PY-001", "dynamic_execution.py", 5, "eval") in rules
    assert ("PKGWHY-PY-001", "dynamic_execution.py", 6, "exec") in rules
    assert ("PKGWHY-PY-001", "dynamic_execution.py", 7, "compile") in rules
    assert ("PKGWHY-PY-002", "dynamic_execution.py", 8, "__import__") in rules
    assert ("PKGWHY-PY-002", "dynamic_execution.py", 9, "importlib.import_module") in rules
    assert ("PKGWHY-PY-003", "deserialisation.py", 6, "pickle.loads") in rules
    assert ("PKGWHY-PY-003", "deserialisation.py", 7, "marshal.loads") in rules
    assert ("PKGWHY-PY-004", "encoded_payloads.py", 4, "large encoded-looking string literal") in rules
    assert ("PKGWHY-PY-004", "encoded_payloads.py", 8, "base64.b64decode") in rules
    assert ("PKGWHY-PY-004", "encoded_payloads.py", 9, "zlib.decompress") in rules
    assert ("PKGWHY-PY-005", "process_environment_package_manager.py", 7, "subprocess.run") in rules
    assert ("PKGWHY-PY-006", "process_environment_package_manager.py", 6, "os.environ") in rules
    assert ("PKGWHY-PY-007", "process_environment_package_manager.py", 7, "subprocess.run") in rules
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

    assert ("PKGWHY-CRED-001", "url_credential_patterns.py", 1, "SERVICE_API_TOKEN") in rules
    assert ("PKGWHY-NET-001", "url_credential_patterns.py", 2, "example.invalid") in rules
    assert analysis.url_references == ["https://example.invalid/..."]
    assert analysis.domain_references == ["example.invalid"]
    assert "placeholdertoken123" not in combined_output
    assert "user:password" not in combined_output
    assert "token=placeholder" not in combined_output

from __future__ import annotations

import re
import tomllib
from collections.abc import Callable
from importlib.metadata import Distribution
from pathlib import Path

from pkgwhy.core.models import FileStaticAnalysis, ReadabilityStatus, RuleSeverity, SourceAvailability
from pkgwhy.inspection.size import JAVASCRIPT_SUFFIXES, NATIVE_SUFFIXES
from pkgwhy.inspection.text_patterns import analyze_text_patterns, is_text_pattern_candidate
from pkgwhy.risk.rules import make_rule_evidence

SHELL_SUFFIXES = {".sh", ".bash", ".zsh", ".fish", ".ksh"}
INSTALL_TIME_SCRIPT_NAMES = {"setup.py"}
BUILD_METADATA_NAMES = {"pyproject.toml", "setup.cfg"}
MAX_TEXT_SCAN_BYTES = 500_000
LONG_JS_LINE_LENGTH = 500
MINIFIED_JS_LINE_LENGTH = 1_000
LOW_WHITESPACE_RATIO = 0.08
HIGH_PUNCTUATION_RATIO = 0.32
JS_LIKELY_OBFUSCATED_WARNING = "likely obfuscated javascript"
JS_POSSIBLY_OBFUSCATED_WARNING = "possibly obfuscated javascript"
JS_APPEARS_MINIFIED_WARNING = "appears minified"
JS_MAY_BE_MINIFIED_WARNING = "may be minified"

JS_DYNAMIC_PATTERNS = {
    re.compile(r"\beval\s*\("): "JavaScript eval call",
    re.compile(r"\bFunction\s*\("): "JavaScript Function constructor",
}
JS_ENCODED_PATTERNS = {
    re.compile(r"\batob\s*\("): "JavaScript base64 decode call",
    re.compile(r"\bbtoa\s*\("): "JavaScript base64 encode call",
}
JS_OBFUSCATION_PATTERNS = {
    re.compile(r"_0x[a-fA-F0-9]{3,}"): "hex-like JavaScript identifier",
    re.compile(r"\\x[0-9a-fA-F]{2}"): "hex-escaped JavaScript string content",
    re.compile(r"while\s*\(\s*!!\[\]\s*\)"): "control-flow flattening pattern",
    re.compile(r"debugger\s*;"): "JavaScript anti-debugging statement",
}
JS_LARGE_ENCODED_PATTERN = re.compile(r"['\"][A-Za-z0-9+/]{80,}={0,2}['\"]")
JS_SOURCE_MAP_PATTERN = re.compile(r"sourceMappingURL\s*=", re.IGNORECASE)
SETUP_SUBPROCESS_PATTERN = re.compile(r"\b(subprocess|os\.system|os\.popen|Popen|check_call|check_output)\b")
SETUP_NETWORK_PATTERN = re.compile(r"\b(requests|httpx|urllib|socket|urlopen)\b")
SETUP_DYNAMIC_PATTERN = re.compile(r"\b(eval|exec|compile|__import__|importlib\.import_module)\b")


def distribution_file_paths(dist: Distribution | None, limit: int = 200) -> list[Path]:
    if dist is None or dist.files is None:
        return []
    paths: list[Path] = []
    for package_file in dist.files:
        try:
            path = Path(dist.locate_file(package_file))
        except (OSError, ValueError):
            continue
        try:
            if path.is_file():
                paths.append(path)
        except OSError:
            continue
        if len(paths) >= limit:
            break
    return paths


def infer_source_availability(paths: list[Path]) -> SourceAvailability:
    if not paths:
        return SourceAvailability.INSTALLED_METADATA_ONLY
    if any(path.suffix == ".py" for path in paths):
        return SourceAvailability.INSTALLED_SOURCE_PRESENT
    return SourceAvailability.SOURCE_AVAILABILITY_UNKNOWN


def infer_readability(paths: list[Path], file_analysis: FileStaticAnalysis | None = None) -> ReadabilityStatus:
    if any(path.suffix == ".py" for path in paths):
        return ReadabilityStatus.READABLE
    if file_analysis and any(JS_LIKELY_OBFUSCATED_WARNING in warning.lower() for warning in file_analysis.warnings):
        return ReadabilityStatus.LIKELY_OBFUSCATED
    if file_analysis and any(JS_POSSIBLY_OBFUSCATED_WARNING in warning.lower() for warning in file_analysis.warnings):
        return ReadabilityStatus.POSSIBLY_OBFUSCATED
    if file_analysis and any(
        marker in warning.lower()
        for warning in file_analysis.warnings
        for marker in {JS_APPEARS_MINIFIED_WARNING, JS_MAY_BE_MINIFIED_WARNING}
    ):
        return ReadabilityStatus.MINIFIED
    return ReadabilityStatus.NOT_ENOUGH_SOURCE_AVAILABLE


def detect_file_capabilities(paths: list[Path], entry_points: list[str]) -> list[str]:
    return analyze_file_signals(paths, entry_points).detected_capabilities


def analyze_file_signals(paths: list[Path], entry_points: list[str]) -> FileStaticAnalysis:
    capabilities: set[str] = set()
    warnings: list[str] = []
    evidence: list[str] = []
    rule_evidence = []
    url_references: list[str] = []
    domain_references: list[str] = []
    credential_references: list[str] = []
    javascript_files_scanned = 0
    shell_scripts_detected = 0
    native_binaries_detected = 0
    wasm_files_detected = 0
    setup_files_detected = 0

    if entry_points:
        capabilities.add("CLI or plugin entrypoints declared in package metadata")
        evidence.append("Package metadata declares CLI or plugin entrypoints.")

    for path in paths:
        suffix = path.suffix.lower()
        name = path.name
        if is_text_pattern_candidate(path):
            text_result = analyze_text_patterns(path)
            capabilities.update(text_result.detected_capabilities)
            warnings.extend(text_result.warnings)
            evidence.extend(text_result.evidence)
            rule_evidence.extend(text_result.rule_evidence)
            url_references.extend(text_result.url_references)
            domain_references.extend(text_result.domain_references)
            credential_references.extend(text_result.credential_references)
        if suffix in NATIVE_SUFFIXES:
            if suffix == ".wasm":
                wasm_files_detected += 1
                capabilities.add("WASM binary code present")
                evidence.append(f"WASM file present: {name}")
                rule_evidence.append(
                    make_rule_evidence(
                        "PKGWHY-BIN-002",
                        message="WebAssembly binary file is present.",
                        evidence=[f"WASM file present: {name}."],
                        file_path=name,
                        symbol=suffix,
                    )
                )
            else:
                native_binaries_detected += 1
                capabilities.add("Native compiled code present")
                evidence.append(f"Native or executable file present: {name}")
                binary_rule_id = "PKGWHY-BIN-003" if suffix == ".exe" else "PKGWHY-BIN-001"
                rule_evidence.append(
                    make_rule_evidence(
                        binary_rule_id,
                        message=f"Native or executable file present: {name}.",
                        evidence=[f"File extension {suffix} detected for {name}."],
                        file_path=name,
                        symbol=suffix,
                    )
                )
        if suffix in JAVASCRIPT_SUFFIXES:
            capabilities.add("Browser or JavaScript code present")
            js_result = _analyze_javascript_file(path)
            javascript_files_scanned += js_result.javascript_files_scanned
            capabilities.update(js_result.detected_capabilities)
            warnings.extend(js_result.warnings)
            evidence.extend(js_result.evidence)
            rule_evidence.extend(js_result.rule_evidence)
        if _is_shell_script(path):
            shell_scripts_detected += 1
            capabilities.add("Shell script files present")
            evidence.append(f"Shell script file present: {name}")
        if name in INSTALL_TIME_SCRIPT_NAMES:
            setup_result = _analyze_setup_py(path)
            setup_files_detected += 1
            capabilities.update(setup_result.detected_capabilities)
            warnings.extend(setup_result.warnings)
            evidence.extend(setup_result.evidence)
            rule_evidence.extend(setup_result.rule_evidence)
        elif name in BUILD_METADATA_NAMES:
            build_result = _analyze_build_metadata(path)
            warnings.extend(build_result.warnings)
            evidence.extend(build_result.evidence)
            rule_evidence.extend(build_result.rule_evidence)

    return FileStaticAnalysis(
        detected_capabilities=sorted(capabilities),
        warnings=warnings[:100],
        evidence=evidence[:100],
        rule_evidence=rule_evidence[:100],
        url_references=_unique(url_references)[:100],
        domain_references=_unique(domain_references)[:100],
        credential_references=_unique(credential_references)[:100],
        javascript_files_scanned=javascript_files_scanned,
        shell_scripts_detected=shell_scripts_detected,
        native_binaries_detected=native_binaries_detected,
        wasm_files_detected=wasm_files_detected,
        setup_files_detected=setup_files_detected,
    )


def _analyze_setup_py(path: Path) -> FileStaticAnalysis:
    name = path.name
    capabilities = {"Install-time setup files present"}
    warnings = [
        "setup.py is executable Python used by some build/install flows. pkgwhy reports static signals only and does not run it."
    ]
    evidence = [f"Install-time setup script present: {name}"]
    rule_evidence = [
        make_rule_evidence(
            "PKGWHY-BUILD-001",
            message="Executable setup.py file is present.",
            evidence=[f"{name} is present."],
            file_path=name,
            symbol="setup.py",
        )
    ]
    source = _read_small_text(path)
    if source is None:
        return FileStaticAnalysis(
            detected_capabilities=sorted(capabilities),
            warnings=warnings,
            evidence=evidence,
            rule_evidence=rule_evidence,
        )

    for rule_id, capability, pattern, detail in (
        ("PKGWHY-BUILD-002", "Subprocess or shell execution signals", SETUP_SUBPROCESS_PATTERN, "subprocess or shell reference"),
        ("PKGWHY-BUILD-003", "Network access signals", SETUP_NETWORK_PATTERN, "network access reference"),
        ("PKGWHY-BUILD-004", "Dynamic code execution signals", SETUP_DYNAMIC_PATTERN, "dynamic execution reference"),
    ):
        line_number = _first_matching_line(source, pattern)
        if line_number is None:
            continue
        capabilities.add(capability)
        warnings.append(f"setup.py contains {detail}: {name}:{line_number}")
        evidence.append(f"setup.py static signal in {name}:{line_number}: {detail}.")
        rule_evidence.append(
            make_rule_evidence(
                rule_id,
                message=f"setup.py contains {detail}.",
                evidence=[f"{name}:{line_number} contains {detail}."],
                file_path=name,
                line_number=line_number,
                symbol=detail,
            )
        )

    return FileStaticAnalysis(
        detected_capabilities=sorted(capabilities),
        warnings=warnings,
        evidence=evidence,
        rule_evidence=rule_evidence,
    )


def _analyze_build_metadata(path: Path) -> FileStaticAnalysis:
    if path.name == "setup.cfg":
        return FileStaticAnalysis(
            evidence=["setup.cfg metadata file present."],
            rule_evidence=[
                make_rule_evidence(
                    "PKGWHY-BUILD-006",
                    message="setup.cfg metadata file is present.",
                    evidence=["setup.cfg is present."],
                    file_path=path.name,
                    symbol="setup.cfg",
                )
            ],
        )

    try:
        source = path.read_text(encoding="utf-8")
        data = tomllib.loads(source)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return FileStaticAnalysis(warnings=[f"Could not statically parse pyproject.toml: {exc.__class__.__name__}"])

    build_system = data.get("build-system")
    if not isinstance(build_system, dict):
        return FileStaticAnalysis(evidence=["pyproject.toml present without build-system table."])

    backend = build_system.get("build-backend")
    if not isinstance(backend, str) or not backend.strip():
        return FileStaticAnalysis(evidence=["pyproject.toml build-system table present without build-backend."])

    line_number = _first_matching_line(source, re.compile(r"build-backend\s*="))
    evidence = [f"pyproject.toml declares build backend: {backend}"]
    return FileStaticAnalysis(
        evidence=evidence,
        rule_evidence=[
            make_rule_evidence(
                "PKGWHY-BUILD-005",
                message=f"Build backend declared: {backend}.",
                evidence=evidence,
                file_path=path.name,
                line_number=line_number,
                symbol=backend,
            )
        ],
    )


def _analyze_javascript_file(path: Path) -> FileStaticAnalysis:
    try:
        if path.stat().st_size > MAX_TEXT_SCAN_BYTES:
            return FileStaticAnalysis(
                warnings=[f"Skipped large JavaScript file during static scan: {path.name}"],
            )
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return FileStaticAnalysis(
            warnings=[f"Could not statically read JavaScript file {path.name}: {exc.__class__.__name__}"],
        )

    capabilities: set[str] = set()
    warnings: list[str] = []
    evidence: list[str] = [f"Statically scanned JavaScript file: {path.name}"]
    rule_evidence = []

    lines = source.splitlines() or [source]
    longest_line = max((len(line) for line in lines), default=0)
    whitespace_ratio = _character_ratio(source, str.isspace)
    punctuation_ratio = _character_ratio(source, lambda char: not char.isalnum() and not char.isspace())

    if path.name.endswith(".min.js") or longest_line >= MINIFIED_JS_LINE_LENGTH:
        warnings.append(f"JavaScript file {JS_APPEARS_MINIFIED_WARNING}: {path.name}")
        evidence.append(f"JavaScript minification signal in {path.name}: long line or .min.js filename.")
        rule_evidence.append(
            make_rule_evidence(
                "PKGWHY-JS-001",
                message="JavaScript file appears minified.",
                evidence=[f"{path.name} has .min.js filename or a line at least {MINIFIED_JS_LINE_LENGTH} characters long."],
                file_path=path.name,
                line_number=_first_long_line(lines, MINIFIED_JS_LINE_LENGTH),
                symbol="minified-javascript",
            )
        )
    elif longest_line >= LONG_JS_LINE_LENGTH and whitespace_ratio < LOW_WHITESPACE_RATIO:
        warnings.append(f"JavaScript file {JS_MAY_BE_MINIFIED_WARNING}: {path.name}")
        evidence.append(f"JavaScript readability signal in {path.name}: long line with low whitespace ratio.")
        rule_evidence.append(
            make_rule_evidence(
                "PKGWHY-JS-001",
                message="JavaScript file may be minified.",
                evidence=[f"{path.name} has a long line with low whitespace ratio."],
                file_path=path.name,
                line_number=_first_long_line(lines, LONG_JS_LINE_LENGTH),
                symbol="minified-javascript",
            )
        )

    if whitespace_ratio < LOW_WHITESPACE_RATIO and punctuation_ratio > HIGH_PUNCTUATION_RATIO:
        warnings.append(f"JavaScript file has low whitespace and high punctuation ratios: {path.name}")
        evidence.append(f"JavaScript density signal in {path.name}: low whitespace and high punctuation.")
        rule_evidence.append(
            make_rule_evidence(
                "PKGWHY-JS-001",
                message="JavaScript file has low whitespace and high punctuation ratios.",
                evidence=[f"{path.name} has low whitespace and high punctuation ratios."],
                file_path=path.name,
                symbol="javascript-density",
            )
        )

    for pattern, detail in JS_DYNAMIC_PATTERNS.items():
        if pattern.search(source):
            capabilities.add("JavaScript dynamic code execution signals")
            evidence.append(f"JavaScript dynamic execution signal in {path.name}: {detail}.")
            rule_evidence.append(
                make_rule_evidence(
                    "PKGWHY-JS-002",
                    message=f"JavaScript dynamic execution signal: {detail}.",
                    evidence=[f"{path.name}:{_first_matching_line(source, pattern) or 1} references {detail}."],
                    file_path=path.name,
                    line_number=_first_matching_line(source, pattern),
                    symbol=detail,
                )
            )

    for pattern, detail in JS_ENCODED_PATTERNS.items():
        if pattern.search(source):
            capabilities.add("Encoded payload handling signals")
            evidence.append(f"JavaScript encoded payload signal in {path.name}: {detail}.")
            rule_evidence.append(
                make_rule_evidence(
                    "PKGWHY-JS-003",
                    message=f"JavaScript encoded payload signal: {detail}.",
                    evidence=[f"{path.name}:{_first_matching_line(source, pattern) or 1} references {detail}."],
                    file_path=path.name,
                    line_number=_first_matching_line(source, pattern),
                    symbol=detail,
                )
            )

    large_encoded_line = _first_matching_line(source, JS_LARGE_ENCODED_PATTERN)
    if large_encoded_line is not None:
        capabilities.add("Encoded payload handling signals")
        evidence.append(f"JavaScript large encoded-string signal in {path.name}:{large_encoded_line}.")
        rule_evidence.append(
            make_rule_evidence(
                "PKGWHY-JS-003",
                message="JavaScript large encoded-string signal detected.",
                evidence=[f"{path.name}:{large_encoded_line} contains a large encoded-looking string; value omitted."],
                file_path=path.name,
                line_number=large_encoded_line,
                symbol="large encoded-looking string",
            )
        )

    source_map_line = _first_matching_line(source, JS_SOURCE_MAP_PATTERN)
    if source_map_line is not None:
        evidence.append(f"JavaScript source-map reference in {path.name}:{source_map_line}.")
        rule_evidence.append(
            make_rule_evidence(
                "PKGWHY-JS-005",
                message="JavaScript source-map reference detected.",
                evidence=[f"{path.name}:{source_map_line} references sourceMappingURL."],
                file_path=path.name,
                line_number=source_map_line,
                symbol="sourceMappingURL",
            )
        )

    obfuscation_signals = [
        detail for pattern, detail in JS_OBFUSCATION_PATTERNS.items() if pattern.search(source)
    ]
    if len(obfuscation_signals) >= 3:
        warnings.append(f"JavaScript file has {JS_LIKELY_OBFUSCATED_WARNING} signals: {path.name}")
        capabilities.add("JavaScript obfuscation signals")
        evidence.append(f"JavaScript obfuscation signals in {path.name}: {', '.join(sorted(obfuscation_signals))}.")
        rule_evidence.append(
            make_rule_evidence(
                "PKGWHY-JS-004",
                message="JavaScript file has likely obfuscated signals.",
                evidence=[f"{path.name} contains signals: {', '.join(sorted(obfuscation_signals))}."],
                severity=RuleSeverity.HIGH,
                file_path=path.name,
                line_number=_first_obfuscation_line(source),
                symbol="javascript-obfuscation",
            )
        )
    elif len(obfuscation_signals) >= 2:
        warnings.append(f"JavaScript file has {JS_POSSIBLY_OBFUSCATED_WARNING} signals: {path.name}")
        capabilities.add("JavaScript obfuscation signals")
        evidence.append(f"JavaScript obfuscation signals in {path.name}: {', '.join(sorted(obfuscation_signals))}.")
        rule_evidence.append(
            make_rule_evidence(
                "PKGWHY-JS-004",
                message="JavaScript file has possible obfuscation signals.",
                evidence=[f"{path.name} contains signals: {', '.join(sorted(obfuscation_signals))}."],
                file_path=path.name,
                line_number=_first_obfuscation_line(source),
                symbol="javascript-obfuscation",
            )
        )

    return FileStaticAnalysis(
        detected_capabilities=sorted(capabilities),
        warnings=warnings,
        evidence=evidence,
        rule_evidence=rule_evidence,
        javascript_files_scanned=1,
    )


def _read_small_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_TEXT_SCAN_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _first_matching_line(source: str, pattern: re.Pattern[str]) -> int | None:
    for index, line in enumerate(source.splitlines(), start=1):
        if pattern.search(line):
            return index
    return None


def _first_long_line(lines: list[str], minimum_length: int) -> int | None:
    for index, line in enumerate(lines, start=1):
        if len(line) >= minimum_length:
            return index
    return None


def _first_obfuscation_line(source: str) -> int | None:
    matching_lines = [
        line_number
        for pattern in JS_OBFUSCATION_PATTERNS
        if (line_number := _first_matching_line(source, pattern)) is not None
    ]
    return min(matching_lines) if matching_lines else None


def _is_shell_script(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in SHELL_SUFFIXES:
        return True
    try:
        with path.open("rb") as handle:
            first_line = handle.readline(128)
    except OSError:
        return False
    return first_line.startswith(b"#!") and b"sh" in first_line.lower()


def _character_ratio(source: str, predicate: Callable[[str], bool]) -> float:
    if not source:
        return 0.0
    return sum(1 for char in source if predicate(char)) / len(source)


def _unique(values: list[str]) -> list[str]:
    unique_values: list[str] = []
    for value in values:
        if value not in unique_values:
            unique_values.append(value)
    return unique_values

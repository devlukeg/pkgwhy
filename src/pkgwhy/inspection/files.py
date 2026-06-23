from __future__ import annotations

import re
from collections.abc import Callable
from importlib.metadata import Distribution
from pathlib import Path

from pkgwhy.core.models import FileStaticAnalysis, ReadabilityStatus, SourceAvailability
from pkgwhy.inspection.size import JAVASCRIPT_SUFFIXES, NATIVE_SUFFIXES

SHELL_SUFFIXES = {".sh", ".bash", ".zsh", ".fish", ".ksh"}
INSTALL_TIME_SCRIPT_NAMES = {"setup.py"}
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
    r"\beval\s*\(": "JavaScript eval call",
    r"\bFunction\s*\(": "JavaScript Function constructor",
}
JS_ENCODED_PATTERNS = {
    r"\batob\s*\(": "JavaScript base64 decode call",
    r"\bbtoa\s*\(": "JavaScript base64 encode call",
}
JS_OBFUSCATION_PATTERNS = {
    r"_0x[a-fA-F0-9]{3,}": "hex-like JavaScript identifier",
    r"\\x[0-9a-fA-F]{2}": "hex-escaped JavaScript string content",
    r"while\s*\(\s*!!\[\]\s*\)": "control-flow flattening pattern",
    r"debugger\s*;": "JavaScript anti-debugging statement",
}


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
    if any(path.suffix == ".py" for path in paths):
        return ReadabilityStatus.READABLE
    return ReadabilityStatus.NOT_ENOUGH_SOURCE_AVAILABLE


def detect_file_capabilities(paths: list[Path], entry_points: list[str]) -> list[str]:
    return analyze_file_signals(paths, entry_points).detected_capabilities


def analyze_file_signals(paths: list[Path], entry_points: list[str]) -> FileStaticAnalysis:
    capabilities: set[str] = set()
    warnings: list[str] = []
    evidence: list[str] = []
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
        if suffix in NATIVE_SUFFIXES:
            if suffix == ".wasm":
                wasm_files_detected += 1
                capabilities.add("WASM binary code present")
                evidence.append(f"WASM file present: {name}")
            else:
                native_binaries_detected += 1
                capabilities.add("Native compiled code present")
                evidence.append(f"Native or executable file present: {name}")
        if suffix in JAVASCRIPT_SUFFIXES:
            capabilities.add("Browser or JavaScript code present")
            js_result = _analyze_javascript_file(path)
            javascript_files_scanned += js_result.javascript_files_scanned
            capabilities.update(js_result.detected_capabilities)
            warnings.extend(js_result.warnings)
            evidence.extend(js_result.evidence)
        if _is_shell_script(path):
            shell_scripts_detected += 1
            capabilities.add("Shell script files present")
            evidence.append(f"Shell script file present: {name}")
        if name in INSTALL_TIME_SCRIPT_NAMES:
            setup_files_detected += 1
            capabilities.add("Install-time setup files present")
            evidence.append(f"Install-time setup script present: {name}")

    return FileStaticAnalysis(
        detected_capabilities=sorted(capabilities),
        warnings=warnings[:100],
        evidence=evidence[:100],
        javascript_files_scanned=javascript_files_scanned,
        shell_scripts_detected=shell_scripts_detected,
        native_binaries_detected=native_binaries_detected,
        wasm_files_detected=wasm_files_detected,
        setup_files_detected=setup_files_detected,
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

    lines = source.splitlines() or [source]
    longest_line = max((len(line) for line in lines), default=0)
    whitespace_ratio = _character_ratio(source, str.isspace)
    punctuation_ratio = _character_ratio(source, lambda char: not char.isalnum() and not char.isspace())

    if path.name.endswith(".min.js") or longest_line >= MINIFIED_JS_LINE_LENGTH:
        warnings.append(f"JavaScript file {JS_APPEARS_MINIFIED_WARNING}: {path.name}")
        evidence.append(f"JavaScript minification signal in {path.name}: long line or .min.js filename.")
    elif longest_line >= LONG_JS_LINE_LENGTH and whitespace_ratio < LOW_WHITESPACE_RATIO:
        warnings.append(f"JavaScript file {JS_MAY_BE_MINIFIED_WARNING}: {path.name}")
        evidence.append(f"JavaScript readability signal in {path.name}: long line with low whitespace ratio.")

    if whitespace_ratio < LOW_WHITESPACE_RATIO and punctuation_ratio > HIGH_PUNCTUATION_RATIO:
        warnings.append(f"JavaScript file has low whitespace and high punctuation ratios: {path.name}")
        evidence.append(f"JavaScript density signal in {path.name}: low whitespace and high punctuation.")

    for pattern, detail in JS_DYNAMIC_PATTERNS.items():
        if re.search(pattern, source):
            capabilities.add("JavaScript dynamic code execution signals")
            evidence.append(f"JavaScript dynamic execution signal in {path.name}: {detail}.")

    for pattern, detail in JS_ENCODED_PATTERNS.items():
        if re.search(pattern, source):
            capabilities.add("Encoded payload handling signals")
            evidence.append(f"JavaScript encoded payload signal in {path.name}: {detail}.")

    obfuscation_signals = [
        detail for pattern, detail in JS_OBFUSCATION_PATTERNS.items() if re.search(pattern, source)
    ]
    likely_threshold = max(3, len(JS_OBFUSCATION_PATTERNS) - 1)
    if len(obfuscation_signals) >= likely_threshold:
        warnings.append(f"JavaScript file has {JS_LIKELY_OBFUSCATED_WARNING} signals: {path.name}")
        capabilities.add("JavaScript obfuscation signals")
        evidence.append(f"JavaScript obfuscation signals in {path.name}: {', '.join(sorted(obfuscation_signals))}.")
    elif len(obfuscation_signals) >= 2:
        warnings.append(f"JavaScript file has {JS_POSSIBLY_OBFUSCATED_WARNING} signals: {path.name}")
        capabilities.add("JavaScript obfuscation signals")
        evidence.append(f"JavaScript obfuscation signals in {path.name}: {', '.join(sorted(obfuscation_signals))}.")

    return FileStaticAnalysis(
        detected_capabilities=sorted(capabilities),
        warnings=warnings,
        evidence=evidence,
        javascript_files_scanned=1,
    )


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

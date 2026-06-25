from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from pkgwhy.core.models import PythonStaticAnalysis
from pkgwhy.risk.rules import make_rule_evidence

MAX_STATIC_FILES = 200
MAX_STATIC_FILE_BYTES = 1_000_000

IMPORT_CAPABILITIES = {
    "os": "Filesystem access signals",
    "pathlib": "Filesystem access signals",
    "shutil": "Filesystem access signals",
    "glob": "Filesystem access signals",
    "socket": "Network access signals",
    "ssl": "Network access signals",
    "urllib": "Network access signals",
    "http.client": "Network access signals",
    "requests": "Network access signals",
    "httpx": "Network access signals",
    "subprocess": "Subprocess or shell execution signals",
    "pty": "Subprocess or shell execution signals",
    "pickle": "Deserialisation risk signals",
    "marshal": "Deserialisation risk signals",
    "shelve": "Deserialisation risk signals",
    "dill": "Deserialisation risk signals",
    "cloudpickle": "Deserialisation risk signals",
    "base64": "Encoded payload handling signals",
    "zlib": "Encoded payload handling signals",
    "importlib": "Dynamic import signals",
}

CALL_CAPABILITIES = {
    "eval": "Dynamic code execution signals",
    "exec": "Dynamic code execution signals",
    "compile": "Dynamic code execution signals",
    "__import__": "Dynamic import signals",
    "importlib.import_module": "Dynamic import signals",
    "subprocess.run": "Subprocess or shell execution signals",
    "subprocess.Popen": "Subprocess or shell execution signals",
    "subprocess.call": "Subprocess or shell execution signals",
    "subprocess.check_call": "Subprocess or shell execution signals",
    "subprocess.check_output": "Subprocess or shell execution signals",
    "os.system": "Subprocess or shell execution signals",
    "os.popen": "Subprocess or shell execution signals",
    "os.execv": "Subprocess or shell execution signals",
    "os.execve": "Subprocess or shell execution signals",
    "os.spawnv": "Subprocess or shell execution signals",
    "os.getenv": "Environment variable access signals",
    "pickle.load": "Deserialisation risk signals",
    "pickle.loads": "Deserialisation risk signals",
    "marshal.loads": "Deserialisation risk signals",
    "dill.loads": "Deserialisation risk signals",
    "cloudpickle.loads": "Deserialisation risk signals",
    "base64.b64decode": "Encoded payload handling signals",
    "zlib.decompress": "Encoded payload handling signals",
    "yaml.load": "Deserialisation risk signals",
}

CALL_RULE_IDS = {
    "eval": "PKGWHY-PY-001",
    "exec": "PKGWHY-PY-001",
    "compile": "PKGWHY-PY-001",
    "__import__": "PKGWHY-PY-002",
    "importlib.import_module": "PKGWHY-PY-002",
    "pickle.load": "PKGWHY-PY-003",
    "pickle.loads": "PKGWHY-PY-003",
    "marshal.loads": "PKGWHY-PY-003",
    "dill.loads": "PKGWHY-PY-003",
    "cloudpickle.loads": "PKGWHY-PY-003",
    "base64.b64decode": "PKGWHY-PY-004",
    "zlib.decompress": "PKGWHY-PY-004",
    "subprocess.run": "PKGWHY-PY-005",
    "subprocess.Popen": "PKGWHY-PY-005",
    "subprocess.call": "PKGWHY-PY-005",
    "subprocess.check_call": "PKGWHY-PY-005",
    "subprocess.check_output": "PKGWHY-PY-005",
    "os.system": "PKGWHY-PY-005",
    "os.popen": "PKGWHY-PY-005",
    "os.execv": "PKGWHY-PY-005",
    "os.execve": "PKGWHY-PY-005",
    "os.spawnv": "PKGWHY-PY-005",
    "os.getenv": "PKGWHY-PY-006",
    "yaml.load": "PKGWHY-PY-008",
}

CREDENTIAL_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"(^|[^a-z0-9])api[_-]?key([^a-z0-9]|$)",
        r"(^|[^a-z0-9])token([^a-z0-9]|$)",
        r"(^|[^a-z0-9])secret([^a-z0-9]|$)",
        r"(^|[^a-z0-9])password([^a-z0-9]|$)",
        r"(^|[^a-z0-9])credential([^a-z0-9]|$)",
    )
)

PACKAGE_MANAGER_PATTERN = re.compile(
    r"(\bpython\s+-m\s+pip\b|\bpip3?\s+(install|uninstall|remove)|\buv\s+(add|remove|sync|pip)|\bpoetry\s+(add|remove|install))"
)
LARGE_ENCODED_LITERAL_PATTERN = re.compile(r"^[A-Za-z0-9+/]{120,}={0,2}$")
PYTHON_OBFUSCATION_BOOTSTRAP_PATTERN = re.compile(
    r"(__pyarmor__|pyarmor_runtime|pytransform|__armor_enter__|__armor_exit__)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PythonSignal:
    capability: str
    detail: str
    rule_id: str | None = None
    line_number: int | None = None
    symbol: str | None = None


def analyze_python_files(paths: list[Path]) -> PythonStaticAnalysis:
    capabilities: set[str] = set()
    warnings: list[str] = []
    evidence: list[str] = []
    rule_evidence = []
    files_scanned = 0

    for path in [item for item in paths if item.suffix == ".py"][:MAX_STATIC_FILES]:
        try:
            if path.stat().st_size > MAX_STATIC_FILE_BYTES:
                warnings.append(f"Skipped large Python file during static scan: {path.name}")
                continue
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            warnings.append(f"Could not statically parse Python file {path.name}: {exc.__class__.__name__}")
            continue

        files_scanned += 1
        file_capabilities = _capabilities_from_tree(tree)
        for signal in file_capabilities:
            capabilities.add(signal.capability)
            location = f"{path.name}:{signal.line_number}" if signal.line_number else path.name
            evidence.append(f"{signal.capability}: {location} references {signal.detail}")
            if signal.rule_id:
                rule_evidence.append(
                    make_rule_evidence(
                        signal.rule_id,
                        message=f"{signal.capability}: {signal.detail}.",
                        evidence=[f"{location} references {signal.detail}."],
                        file_path=path.name,
                        line_number=signal.line_number,
                        symbol=signal.symbol or signal.detail,
                    )
                )

    return PythonStaticAnalysis(
        detected_capabilities=sorted(capabilities),
        warnings=warnings,
        evidence=evidence[:100],
        rule_evidence=rule_evidence[:100],
        files_scanned=files_scanned,
    )


def _capabilities_from_tree(tree: ast.AST) -> list[PythonSignal]:
    detected: dict[tuple[str, str, int | None], PythonSignal] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for imported_name in _imported_names(node):
                capability = _capability_for_import(imported_name)
                if capability:
                    _add_signal(
                        detected,
                        PythonSignal(
                            capability=capability,
                            detail=imported_name,
                            line_number=getattr(node, "lineno", None),
                            symbol=imported_name,
                        ),
                    )
        elif isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            capability = CALL_CAPABILITIES.get(call_name)
            if capability:
                _add_signal(
                    detected,
                    PythonSignal(
                        capability=capability,
                        detail=call_name,
                        rule_id=CALL_RULE_IDS.get(call_name),
                        line_number=getattr(node, "lineno", None),
                        symbol=call_name,
                    ),
                )
            if _is_package_manager_call(call_name, node):
                _add_signal(
                    detected,
                    PythonSignal(
                        capability="Package manager manipulation signals",
                        detail=call_name,
                        rule_id="PKGWHY-PY-007",
                        line_number=getattr(node, "lineno", None),
                        symbol=call_name,
                    ),
                )
        elif isinstance(node, ast.Attribute):
            attr_name = _call_name(node)
            if attr_name == "os.environ":
                _add_signal(
                    detected,
                    PythonSignal(
                        capability="Environment variable access signals",
                        detail=attr_name,
                        rule_id="PKGWHY-PY-006",
                        line_number=getattr(node, "lineno", None),
                        symbol=attr_name,
                    ),
                )
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            lowered = node.value.lower()
            if any(pattern.search(lowered) for pattern in CREDENTIAL_PATTERNS):
                _add_signal(
                    detected,
                    PythonSignal(
                        capability="Credential or token access patterns",
                        detail="string literal containing credential-like token",
                        rule_id="PKGWHY-PY-006",
                        line_number=getattr(node, "lineno", None),
                        symbol="credential-like string literal",
                    ),
                )
            if LARGE_ENCODED_LITERAL_PATTERN.fullmatch(node.value.strip()):
                _add_signal(
                    detected,
                    PythonSignal(
                        capability="Encoded payload handling signals",
                        detail="large encoded-looking string literal",
                        rule_id="PKGWHY-PY-004",
                        line_number=getattr(node, "lineno", None),
                        symbol="large encoded-looking string literal",
                    ),
                )
            if PYTHON_OBFUSCATION_BOOTSTRAP_PATTERN.search(node.value):
                _add_signal(
                    detected,
                    PythonSignal(
                        capability="Python obfuscation signals",
                        detail="obfuscation-bootstrap string literal",
                        rule_id="PKGWHY-PY-009",
                        line_number=getattr(node, "lineno", None),
                        symbol="obfuscation-bootstrap string literal",
                    ),
                )
        elif isinstance(node, ast.Name) and PYTHON_OBFUSCATION_BOOTSTRAP_PATTERN.search(node.id):
            _add_signal(
                detected,
                PythonSignal(
                    capability="Python obfuscation signals",
                    detail=node.id,
                    rule_id="PKGWHY-PY-009",
                    line_number=getattr(node, "lineno", None),
                    symbol=node.id,
                ),
            )
    return list(detected.values())


def _imported_names(node: ast.Import | ast.ImportFrom) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if node.module is None:
        return []
    return [node.module]


def _capability_for_import(imported_name: str) -> str | None:
    parts = imported_name.split(".")
    candidates = [imported_name]
    candidates.append(parts[0])
    for candidate in candidates:
        if candidate in IMPORT_CAPABILITIES:
            return IMPORT_CAPABILITIES[candidate]
    return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _add_signal(detected: dict[tuple[str, str, int | None], PythonSignal], signal: PythonSignal) -> None:
    detected.setdefault((signal.capability, signal.detail, signal.line_number), signal)


def _is_package_manager_call(call_name: str, node: ast.Call) -> bool:
    if call_name in {"pip.main"}:
        return True
    if call_name not in {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
    }:
        return False
    text_args = " ".join(_literal_text_args(node))
    return bool(PACKAGE_MANAGER_PATTERN.search(text_args))


def _literal_text_args(node: ast.Call) -> list[str]:
    values: list[str] = []
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            values.append(arg.value)
        elif isinstance(arg, (ast.List, ast.Tuple)):
            values.extend(item.value for item in arg.elts if isinstance(item, ast.Constant) and isinstance(item.value, str))
    return values

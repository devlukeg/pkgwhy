from __future__ import annotations

import ast
import re
from pathlib import Path

from pkgwhy.core.models import PythonStaticAnalysis

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


def analyze_python_files(paths: list[Path]) -> PythonStaticAnalysis:
    capabilities: set[str] = set()
    warnings: list[str] = []
    evidence: list[str] = []
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
        for capability, detail in file_capabilities:
            capabilities.add(capability)
            evidence.append(f"{capability}: {path.name} references {detail}")

    return PythonStaticAnalysis(
        detected_capabilities=sorted(capabilities),
        warnings=warnings,
        evidence=evidence[:100],
        files_scanned=files_scanned,
    )


def _capabilities_from_tree(tree: ast.AST) -> set[tuple[str, str]]:
    detected: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for imported_name in _imported_names(node):
                capability = _capability_for_import(imported_name)
                if capability:
                    detected.add((capability, imported_name))
        elif isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            capability = CALL_CAPABILITIES.get(call_name)
            if capability:
                detected.add((capability, call_name))
        elif isinstance(node, ast.Attribute):
            attr_name = _call_name(node)
            if attr_name == "os.environ":
                detected.add(("Environment variable access signals", attr_name))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            lowered = node.value.lower()
            if any(pattern.search(lowered) for pattern in CREDENTIAL_PATTERNS):
                detected.add(("Credential or token access patterns", "string literal containing credential-like token"))
    return detected


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

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from pkgwhy.core.models import FileStaticAnalysis
from pkgwhy.risk.rules import make_rule_evidence

MAX_TEXT_PATTERN_BYTES = 500_000
TEXT_PATTERN_SUFFIXES = {
    ".cfg",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

URL_PATTERN = re.compile(r"https?://[^\s'\"<>)\]}]+", re.IGNORECASE)
CREDENTIAL_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*(?:api[_-]?key|token|secret|password|credential)[A-Za-z0-9_]*)\b"
    r"\s*[:=]\s*"
    r"(?P<quote>['\"]?)"
    r"(?P<value>[A-Za-z0-9_\-./+=]{8,})"
    r"(?P=quote)",
    re.IGNORECASE,
)


def analyze_text_patterns(path: Path) -> FileStaticAnalysis:
    """Extract conservative URL/domain and credential-like text signals."""

    source = _read_small_text(path)
    if source is None:
        return FileStaticAnalysis()

    url_references: list[str] = []
    domain_references: list[str] = []
    credential_references: list[str] = []
    capabilities: set[str] = set()
    evidence: list[str] = []
    rule_evidence = []

    for line_number, line in enumerate(source.splitlines(), start=1):
        for match in URL_PATTERN.finditer(line):
            sanitized_url = _sanitize_url(match.group(0))
            domain = _domain_from_url(match.group(0))
            if not sanitized_url or not domain:
                continue
            capabilities.add("URL or domain references")
            _append_unique(url_references, sanitized_url)
            _append_unique(domain_references, domain)
            evidence.append(f"URL/domain reference in {path.name}:{line_number}: {domain}.")
            rule_evidence.append(
                make_rule_evidence(
                    "PKGWHY-NET-001",
                    message=f"Source text references URL/domain {domain}.",
                    evidence=[f"{path.name}:{line_number} references domain {domain}."],
                    file_path=path.name,
                    line_number=line_number,
                    symbol=domain,
                )
            )

        for match in CREDENTIAL_ASSIGNMENT_PATTERN.finditer(line):
            credential_name = match.group("name")
            capabilities.add("Credential or token access patterns")
            reference = f"{path.name}:{line_number}:{credential_name}=[masked]"
            _append_unique(credential_references, reference)
            evidence.append(f"Credential-like assignment in {path.name}:{line_number}: {credential_name}=[masked].")
            rule_evidence.append(
                make_rule_evidence(
                    "PKGWHY-CRED-001",
                    message=f"Credential-like assignment references {credential_name}; value masked.",
                    evidence=[f"{path.name}:{line_number} contains {credential_name}=[masked]."],
                    file_path=path.name,
                    line_number=line_number,
                    symbol=credential_name,
                )
            )

    return FileStaticAnalysis(
        detected_capabilities=sorted(capabilities),
        evidence=evidence,
        rule_evidence=rule_evidence,
        url_references=url_references,
        domain_references=domain_references,
        credential_references=credential_references,
    )


def is_text_pattern_candidate(path: Path) -> bool:
    return path.suffix.lower() in TEXT_PATTERN_SUFFIXES or path.name in {"setup.py", "setup.cfg", "pyproject.toml"}


def _read_small_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_TEXT_PATTERN_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _sanitize_url(raw_url: str) -> str | None:
    cleaned = raw_url.rstrip(".,;:")
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    host = parsed.hostname
    if not host:
        return None
    path = "/..." if parsed.path and parsed.path != "/" else ""
    return f"{parsed.scheme}://{host.lower()}{path}"


def _domain_from_url(raw_url: str) -> str | None:
    parsed = urlparse(raw_url.rstrip(".,;:"))
    if parsed.scheme not in {"http", "https"}:
        return None
    host = parsed.hostname
    return host.lower() if host else None


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)

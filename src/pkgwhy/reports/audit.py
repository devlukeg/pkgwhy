from __future__ import annotations

import html
from typing import Any, TypedDict

from pkgwhy.core.models import PackageJudgement

AUDIT_SCHEMA_VERSION = "pkgwhy.audit.v2"


class AuditReport(TypedDict):
    schema_version: str
    package_count: int
    vulnerability_match_count: int
    vulnerability_sources: list[str]
    provenance_sources: list[str]
    warnings: list[str]
    packages: list[dict[str, Any]]


def build_audit_report(judgements: list[PackageJudgement], warnings: list[str] | None = None) -> AuditReport:
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "package_count": len(judgements),
        "vulnerability_match_count": sum(len(judgement.known_vulnerabilities) for judgement in judgements),
        "vulnerability_sources": sorted(
            {
                vulnerability.source
                for judgement in judgements
                for vulnerability in judgement.known_vulnerabilities
                if vulnerability.source
            }
        ),
        "provenance_sources": sorted(
            {
                judgement.provenance.metadata_source
                for judgement in judgements
                if judgement.provenance is not None and judgement.provenance.metadata_source
            }
        ),
        "warnings": warnings or [],
        "packages": [judgement.model_dump(mode="json") for judgement in judgements],
    }


def render_audit_markdown(judgements: list[PackageJudgement], warnings: list[str] | None = None) -> str:
    lines = [
        "# pkgwhy Audit Report",
        "",
        "Runtime capability exposure:",
        "",
        "> Python packages run with the same permissions as the Python process. Static signals are not proof of runtime behavior or intent.",
        "",
        "| Package | Version | Risk | Decision | Vulnerabilities | Warnings |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for judgement in judgements:
        warning_count = len(judgement.warnings)
        lines.append(
            "| "
            f"{_escape_markdown_table_cell(judgement.package)} | "
            f"{_escape_markdown_table_cell(judgement.version or 'unknown')} | "
            f"{_escape_markdown_table_cell(judgement.risk_level.value)} | "
            f"{_escape_markdown_table_cell(judgement.decision.value)} | "
            f"{len(judgement.known_vulnerabilities)} | "
            f"{warning_count} |"
        )
    if warnings:
        lines.extend(["", "## Warnings", ""])
        for warning in warnings:
            lines.append(f"- {_escape_markdown_list_item(warning)}")
    return "\n".join(lines) + "\n"


def _escape_markdown_table_cell(value: str) -> str:
    escaped = html.escape(value, quote=False)
    return escaped.replace("\\", r"\\").replace("\r", " ").replace("\n", " ").replace("|", r"\|")


def _escape_markdown_list_item(value: str) -> str:
    return html.escape(value, quote=False).replace("\\", r"\\").replace("\r", " ").replace("\n", " ")

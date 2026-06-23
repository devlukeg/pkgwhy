from __future__ import annotations

from typing import Any, TypedDict

from pkgwhy.core.models import PackageJudgement

AUDIT_SCHEMA_VERSION = "pkgwhy.audit.v1"


class AuditReport(TypedDict):
    schema_version: str
    package_count: int
    packages: list[dict[str, Any]]


def build_audit_report(judgements: list[PackageJudgement]) -> AuditReport:
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "package_count": len(judgements),
        "packages": [judgement.model_dump(mode="json") for judgement in judgements],
    }


def render_audit_markdown(judgements: list[PackageJudgement]) -> str:
    lines = [
        "# pkgwhy Audit Report",
        "",
        "Runtime capability exposure:",
        "",
        "> Python packages run with the same permissions as the Python process. Static signals are not proof of runtime behavior or intent.",
        "",
        "| Package | Version | Risk | Decision | Warnings |",
        "| --- | --- | --- | --- | --- |",
    ]
    for judgement in judgements:
        warning_count = len(judgement.warnings)
        lines.append(
            "| "
            f"{_escape_markdown_table_cell(judgement.package)} | "
            f"{_escape_markdown_table_cell(judgement.version or 'unknown')} | "
            f"{_escape_markdown_table_cell(judgement.risk_level.value)} | "
            f"{_escape_markdown_table_cell(judgement.decision.value)} | "
            f"{warning_count} |"
        )
    return "\n".join(lines) + "\n"


def _escape_markdown_table_cell(value: str) -> str:
    return value.replace("\\", r"\\").replace("\r", " ").replace("\n", " ").replace("|", r"\|")

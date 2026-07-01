from __future__ import annotations

import html
from typing import Any, TypedDict

from pkgwhy.core.decision_contract import (
    compact_evidence_summary,
    exit_code_for_decision,
    exit_code_meaning,
    highest_risk,
    lowest_confidence,
    recommended_next_action,
    strictest_decision,
)
from pkgwhy.core.models import PackageJudgement

AUDIT_SCHEMA_VERSION = "pkgwhy.audit.v2"


class AuditReport(TypedDict):
    schema_version: str
    command: str
    target: str
    target_type: str
    decision: str
    risk_level: str
    confidence: str
    recommended_next_action: str
    exit_code: int
    exit_code_meaning: str
    evidence: list[str]
    evidence_summary: dict[str, object]
    source_freshness: str
    package_count: int
    vulnerability_match_count: int
    vulnerability_sources: list[str]
    provenance_sources: list[str]
    warnings: list[str]
    packages: list[dict[str, Any]]


def build_audit_report(judgements: list[PackageJudgement], warnings: list[str] | None = None) -> AuditReport:
    decision = strictest_decision(judgement.decision for judgement in judgements)
    risk_level = highest_risk(judgement.risk_level for judgement in judgements)
    confidence = lowest_confidence(judgement.confidence for judgement in judgements)
    exit_code = exit_code_for_decision(decision)
    evidence = [
        f"Audited {len(judgements)} installed package(s) from the active Python environment.",
        "Package judgements were built from already-computed metadata and static inspection results.",
    ]
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "command": "pkgwhy audit",
        "target": "active_python_environment",
        "target_type": "environment",
        "decision": decision,
        "risk_level": risk_level,
        "confidence": confidence,
        "recommended_next_action": recommended_next_action(decision),
        "exit_code": exit_code,
        "exit_code_meaning": exit_code_meaning(exit_code),
        "evidence": evidence,
        "evidence_summary": compact_evidence_summary(
            evidence=[*evidence, *(item for judgement in judgements for item in judgement.evidence)],
            warnings=warnings or [],
            risk_rules=[rule for judgement in judgements for rule in judgement.risk_rules],
        ),
        "source_freshness": "installed_environment_snapshot",
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

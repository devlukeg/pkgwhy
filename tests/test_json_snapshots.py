import json
from pathlib import Path

from typer.testing import CliRunner

from pkgwhy.cli import app
from pkgwhy.core.models import (
    AgentPackagePrecheckResult,
    PackageIdentity,
    PackageJudgement,
    PackageMetadata,
    ToolJudgement,
)
from pkgwhy.metadata.installed import normalize_package_name
from pkgwhy.reports.audit import AUDIT_SCHEMA_VERSION

runner = CliRunner()

MISSING_PACKAGE = "definitely-not-installed-pkgwhy-json-snapshot-8d4c1"


def _json_output(args: list[str], *, env: dict[str, str] | None = None) -> dict:
    result = runner.invoke(app, args, env=env)

    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _package_judgement_snapshot(data: dict) -> dict:
    PackageJudgement.model_validate(data)
    provenance = data["provenance"]
    return {
        "top_level_keys": sorted(data),
        "schema_version": data["schema_version"],
        "command": data["command"],
        "target": data["target"],
        "target_type": data["target_type"],
        "risk_model_version": data["risk_model_version"],
        "package": data["package"],
        "version": data["version"],
        "decision": data["decision"],
        "risk_level": data["risk_level"],
        "confidence": data["confidence"],
        "recommended_next_action": data["recommended_next_action"],
        "exit_code": data["exit_code"],
        "exit_code_meaning": data["exit_code_meaning"],
        "evidence_summary_keys": sorted(data["evidence_summary"]),
        "source_freshness": data["source_freshness"],
        "source_availability": data["source_availability"],
        "known_vulnerability_count": len(data["known_vulnerabilities"]),
        "risk_rule_ids": [rule["rule_id"] for rule in data["risk_rules"]],
        "risk_rule_keys": sorted(data["risk_rules"][0]) if data["risk_rules"] else [],
        "provenance_keys": sorted(provenance),
        "provenance_statuses": {
            "metadata_source": provenance["metadata_source"],
            "source_distribution_status": provenance["source_distribution_status"],
            "trusted_publishing_status": provenance["trusted_publishing_status"],
            "attestation_status": provenance["attestation_status"],
            "release_activity_status": provenance["release_activity_status"],
        },
    }


def _agent_package_precheck_snapshot(data: dict) -> dict:
    AgentPackagePrecheckResult.model_validate(data)
    return {
        "top_level_keys": sorted(data),
        "schema_version": data["schema_version"],
        "command": data["command"],
        "target": data["target"],
        "policy_schema_version": data["policy_schema_version"],
        "package": data["package"],
        "version": data["version"],
        "target_type": data["target_type"],
        "non_interactive": data["non_interactive"],
        "decision": data["decision"],
        "risk_level": data["risk_level"],
        "confidence": data["confidence"],
        "recommended_next_action": data["recommended_next_action"],
        "exit_code": data["exit_code"],
        "exit_code_meaning": data["exit_code_meaning"],
        "evidence_summary_keys": sorted(data["evidence_summary"]),
        "policy": data["policy"],
        "source_freshness": data["source_freshness"],
        "policy_decision_source": data["policy_decision_source"],
        "reason_count": len(data["reasons"]),
        "package_judgement_snapshot": _package_judgement_snapshot(data["package_judgement"]),
    }


def test_judge_json_golden_snapshot_for_missing_package(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    data = _json_output(["judge", MISSING_PACKAGE, "--json"], env=env)

    assert _package_judgement_snapshot(data) == {
        "top_level_keys": [
            "capability_exposure_note",
            "command",
            "confidence",
            "decision",
            "detected_capabilities",
            "evidence",
            "evidence_summary",
            "exit_code",
            "exit_code_meaning",
            "installed_size_bytes",
            "known_vulnerabilities",
            "package",
            "provenance",
            "recommendation",
            "recommended_next_action",
            "risk_level",
            "risk_model_version",
            "risk_rules",
            "schema_version",
            "source_availability",
            "source_freshness",
            "summary",
            "target",
            "target_type",
            "version",
            "warnings",
        ],
        "schema_version": "pkgwhy.package_judgement.v1",
        "command": "pkgwhy judge",
        "target": MISSING_PACKAGE,
        "target_type": "package",
        "risk_model_version": "pkgwhy.risk_model.v1",
        "package": MISSING_PACKAGE,
        "version": None,
        "decision": "review_manually",
        "risk_level": "unknown",
        "confidence": "low",
        "recommended_next_action": "Risk is unknown. Manual review recommended.",
        "exit_code": 1,
        "exit_code_meaning": "review or caution required before proceeding",
        "evidence_summary_keys": [
            "evidence_count",
            "highest_rule_severity",
            "risk_rule_count",
            "top_evidence",
            "top_risk_rule_ids",
            "top_warnings",
            "warning_count",
        ],
        "source_freshness": "installed_distribution_metadata",
        "source_availability": "not_installed",
        "known_vulnerability_count": 0,
        "risk_rule_ids": ["PKGWHY-RISK-003", "PKGWHY-RISK-006"],
        "risk_rule_keys": [
            "category",
            "confidence",
            "evidence",
            "false_positive_note",
            "file_path",
            "line_number",
            "message",
            "name",
            "rule_id",
            "severity",
            "symbol",
        ],
        "provenance_keys": [
            "attestation_status",
            "confidence",
            "documentation_url",
            "evidence",
            "homepage_url",
            "metadata_source",
            "package",
            "project_urls",
            "release_activity_status",
            "repository_url",
            "source_distribution_status",
            "trusted_publishing_status",
            "version",
            "warnings",
        ],
        "provenance_statuses": {
            "metadata_source": "installed_distribution_metadata",
            "source_distribution_status": "unknown",
            "trusted_publishing_status": "unknown",
            "attestation_status": "not_implemented",
            "release_activity_status": "unknown",
        },
    }


def test_audit_json_golden_snapshot_for_controlled_package(monkeypatch, tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    package = PackageMetadata(
        identity=PackageIdentity(
            name=MISSING_PACKAGE,
            normalized_name=normalize_package_name(MISSING_PACKAGE),
            version="0.0.0",
        ),
        metadata_available=True,
    )
    monkeypatch.setattr("pkgwhy.cli.list_installed_packages", lambda: [package])

    data = _json_output(["audit", "--limit", "1", "--json"], env=env)

    assert {
        "top_level_keys": sorted(data),
        "schema_version": data["schema_version"],
        "package_count": data["package_count"],
        "vulnerability_match_count": data["vulnerability_match_count"],
        "vulnerability_sources": data["vulnerability_sources"],
        "provenance_sources": data["provenance_sources"],
        "warnings": data["warnings"],
        "package_snapshot": _package_judgement_snapshot(data["packages"][0]),
    } == {
        "top_level_keys": [
            "command",
            "confidence",
            "decision",
            "evidence",
            "evidence_summary",
            "exit_code",
            "exit_code_meaning",
            "package_count",
            "packages",
            "provenance_sources",
            "recommended_next_action",
            "risk_level",
            "schema_version",
            "source_freshness",
            "target",
            "target_type",
            "vulnerability_match_count",
            "vulnerability_sources",
            "warnings",
        ],
        "schema_version": AUDIT_SCHEMA_VERSION,
        "package_count": 1,
        "vulnerability_match_count": 0,
        "vulnerability_sources": [],
        "provenance_sources": ["installed_distribution_metadata"],
        "warnings": [],
        "package_snapshot": _package_judgement_snapshot(_json_output(["judge", MISSING_PACKAGE, "--json"], env=env)),
    }


def test_agent_precheck_json_golden_snapshot_for_missing_package(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    data = _json_output(["agent", "precheck", MISSING_PACKAGE, "--json"], env=env)

    assert _agent_package_precheck_snapshot(data) == {
        "top_level_keys": [
            "command",
            "confidence",
            "decision",
            "evidence",
            "evidence_summary",
            "exit_code",
            "exit_code_meaning",
            "non_interactive",
            "package",
            "package_judgement",
            "policy",
            "policy_decision_source",
            "policy_schema_version",
            "reasons",
            "recommendation",
            "recommended_next_action",
            "risk_level",
            "schema_version",
            "source_freshness",
            "target",
            "target_type",
            "version",
            "warnings",
        ],
        "schema_version": "pkgwhy.agent_package_precheck.v1",
        "command": "pkgwhy agent precheck",
        "target": MISSING_PACKAGE,
        "policy_schema_version": "pkgwhy.agent_policy.v1",
        "package": MISSING_PACKAGE,
        "version": None,
        "target_type": "package",
        "non_interactive": True,
        "decision": "block",
        "risk_level": "unknown",
        "confidence": "low",
        "recommended_next_action": "Block non-interactive package use until a human reviews the judgement evidence.",
        "exit_code": 2,
        "exit_code_meaning": "blocked by policy or risk decision",
        "evidence_summary_keys": [
            "evidence_count",
            "highest_rule_severity",
            "risk_rule_count",
            "top_evidence",
            "top_risk_rule_ids",
            "top_warnings",
            "warning_count",
        ],
        "policy": {
            "decision_source": "agent_policy",
            "non_interactive": True,
            "schema_version": "pkgwhy.agent_policy.v1",
        },
        "source_freshness": "installed_distribution_metadata",
        "policy_decision_source": "agent_policy",
        "reason_count": 2,
        "package_judgement_snapshot": _package_judgement_snapshot(
            _json_output(["judge", MISSING_PACKAGE, "--json"], env=env)
        ),
    }


def test_agent_judge_json_golden_snapshot_for_missing_package(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    data = _json_output(["agent", "judge", MISSING_PACKAGE, "--json"], env=env)

    assert _agent_package_precheck_snapshot(data) == {
        "top_level_keys": [
            "command",
            "confidence",
            "decision",
            "evidence",
            "evidence_summary",
            "exit_code",
            "exit_code_meaning",
            "non_interactive",
            "package",
            "package_judgement",
            "policy",
            "policy_decision_source",
            "policy_schema_version",
            "reasons",
            "recommendation",
            "recommended_next_action",
            "risk_level",
            "schema_version",
            "source_freshness",
            "target",
            "target_type",
            "version",
            "warnings",
        ],
        "schema_version": "pkgwhy.agent_package_precheck.v1",
        "command": "pkgwhy agent precheck",
        "target": MISSING_PACKAGE,
        "policy_schema_version": "pkgwhy.agent_policy.v1",
        "package": MISSING_PACKAGE,
        "version": None,
        "target_type": "package",
        "non_interactive": True,
        "decision": "block",
        "risk_level": "unknown",
        "confidence": "low",
        "recommended_next_action": "Block non-interactive package use until a human reviews the judgement evidence.",
        "exit_code": 2,
        "exit_code_meaning": "blocked by policy or risk decision",
        "evidence_summary_keys": [
            "evidence_count",
            "highest_rule_severity",
            "risk_rule_count",
            "top_evidence",
            "top_risk_rule_ids",
            "top_warnings",
            "warning_count",
        ],
        "policy": {
            "decision_source": "agent_policy",
            "non_interactive": True,
            "schema_version": "pkgwhy.agent_policy.v1",
        },
        "source_freshness": "installed_distribution_metadata",
        "policy_decision_source": "agent_policy",
        "reason_count": 2,
        "package_judgement_snapshot": _package_judgement_snapshot(
            _json_output(["judge", MISSING_PACKAGE, "--json"], env=env)
        ),
    }


def test_tool_judge_json_golden_snapshot(tmp_path: Path) -> None:
    env = {"PKGWHY_CONFIG_HOME": str(tmp_path / "config")}
    registry_path = tmp_path / "registry"
    script = tmp_path / "snapshot_tool.py"
    script.write_text("print('snapshot')\n", encoding="utf-8")

    assert runner.invoke(app, ["registry", "init", str(registry_path)], env=env).exit_code == 0
    assert runner.invoke(app, ["publish", str(script)], env=env).exit_code == 0

    data = _json_output(["tool", "judge", "local/snapshot_tool", "--json"], env=env)
    ToolJudgement.model_validate(data)

    assert {
        "top_level_keys": sorted(data),
        "schema_version": data["schema_version"],
        "command": data["command"],
        "target": data["target"],
        "target_type": data["target_type"],
        "tool": data["tool"],
        "owner": data["owner"],
        "name": data["name"],
        "version": data["version"],
        "decision": data["decision"],
        "risk_level": data["risk_level"],
        "confidence": data["confidence"],
        "exit_code": data["exit_code"],
        "exit_code_meaning": data["exit_code_meaning"],
        "source_freshness": data["source_freshness"],
        "requires_human_approval": data["requires_human_approval"],
        "hash_status": data["hash_status"],
        "signature_status": data["signature_status"],
        "manifest_keys": sorted(data["manifest"]),
        "manifest_schema_version": data["manifest"]["schema_version"],
        "manifest_security": data["manifest"]["security"],
        "manifest_agent": data["manifest"]["agent"],
        "warnings": data["warnings"],
    } == {
        "top_level_keys": [
            "command",
            "confidence",
            "decision",
            "declared_permissions",
            "detected_capabilities",
            "evidence",
            "evidence_summary",
            "exit_code",
            "exit_code_meaning",
            "hash_status",
            "manifest",
            "name",
            "owner",
            "reason",
            "recommendation",
            "recommended_next_action",
            "requires_human_approval",
            "risk_level",
            "schema_version",
            "signature_status",
            "source_freshness",
            "target",
            "target_type",
            "tool",
            "trust_state",
            "version",
            "warnings",
        ],
        "schema_version": "pkgwhy.tool_judgement.v1",
        "command": "pkgwhy tool judge",
        "target": "local/snapshot_tool",
        "target_type": "tool",
        "tool": "local/snapshot_tool",
        "owner": "local",
        "name": "snapshot_tool",
        "version": "0.1.0",
        "decision": "review_manually",
        "risk_level": "medium",
        "confidence": "medium",
        "exit_code": 1,
        "exit_code_meaning": "review or caution required before proceeding",
        "source_freshness": "local_registry_snapshot",
        "requires_human_approval": True,
        "hash_status": "verified",
        "signature_status": "not_implemented",
        "manifest_keys": [
            "agent",
            "artifact_type",
            "declared_permissions",
            "dependencies",
            "description",
            "entrypoint",
            "name",
            "owner",
            "python_requires",
            "schema_version",
            "security",
            "version",
        ],
        "manifest_schema_version": "pkgwhy.tool_manifest.v1",
        "manifest_security": {
            "allow_unpinned_dependencies": False,
            "allow_unsigned": False,
            "requires_human_approval": True,
            "signing_status": "not_implemented",
        },
        "manifest_agent": {
            "default_decision": "review_manually",
            "non_interactive_decision": "review_manually",
        },
        "warnings": [
            "Signature verification is not implemented yet.",
            "Static capability detection for tool bundles is not implemented yet.",
        ],
    }

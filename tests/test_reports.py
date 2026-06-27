import json
import re
from pathlib import Path

from typer.testing import CliRunner

from pkgwhy.cli import app
from pkgwhy.core.models import (
    AgentDecision,
    Confidence,
    PackageIdentity,
    PackageJudgement,
    PackageMetadata,
    RiskLevel,
    SourceAvailability,
)
from pkgwhy.reports.audit import AUDIT_SCHEMA_VERSION, render_audit_markdown
from pkgwhy.vulnerabilities.osv import OSVLookupResult

runner = CliRunner()
ANSI_STYLE_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi_styles(output: str) -> str:
    return ANSI_STYLE_RE.sub("", output)


def test_risk_command_outputs_human_risk_report() -> None:
    result = runner.invoke(app, ["risk", "typer"])

    assert result.exit_code == 0
    assert "Risk level:" in result.output
    assert "Decision:" in result.output
    assert "Recommendation:" in result.output
    assert "Rule evidence" in result.output
    assert "PKGWHY-" in result.output


def test_inspect_command_outputs_rule_evidence() -> None:
    result = runner.invoke(app, ["inspect", "typer"])

    assert result.exit_code == 0
    assert "Rule evidence" in result.output
    assert "PKGWHY-" in result.output


def test_judge_command_outputs_rule_evidence() -> None:
    result = runner.invoke(app, ["judge", "typer"])

    assert result.exit_code == 0
    assert "Rule evidence" in result.output
    assert "PKGWHY-" in result.output


def test_risk_command_outputs_json_report() -> None:
    result = runner.invoke(app, ["risk", "typer", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == "pkgwhy.package_judgement.v1"
    assert data["package"] == "typer"
    assert "risk_level" in data


def test_audit_command_outputs_schema_versioned_json() -> None:
    result = runner.invoke(app, ["audit", "--limit", "1", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == AUDIT_SCHEMA_VERSION
    assert data["package_count"] == 1
    assert len(data["packages"]) == 1
    assert data["packages"][0]["schema_version"] == "pkgwhy.package_judgement.v1"


def test_audit_command_outputs_markdown() -> None:
    result = runner.invoke(app, ["audit", "--limit", "1", "--markdown"])

    assert result.exit_code == 0
    assert "# pkgwhy Audit Report" in result.output
    assert "| Package | Version | Risk | Decision | Vulnerabilities | Warnings |" in result.output


def test_audit_rejects_invalid_output_mode_combination() -> None:
    result = runner.invoke(app, ["audit", "--json", "--markdown"])

    assert result.exit_code != 0
    assert "Choose either --json or --markdown" in strip_ansi_styles(result.output)


def test_audit_rejects_output_without_file_report_mode(tmp_path: Path) -> None:
    output = tmp_path / "audit.txt"
    result = runner.invoke(app, ["audit", "--output", str(output)])

    assert result.exit_code != 0
    assert "--output requires --json or --markdown" in strip_ansi_styles(result.output)


def test_audit_writes_json_report_to_output_path(tmp_path: Path) -> None:
    output = tmp_path / "audit.json"
    result = runner.invoke(app, ["audit", "--limit", "1", "--json", "--output", str(output)])

    assert result.exit_code == 0
    assert output.exists()
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["schema_version"] == AUDIT_SCHEMA_VERSION


def test_audit_pypi_option_uses_source_attributed_provenance_without_live_network(monkeypatch) -> None:
    audited_version = "1.2.3"
    installed = PackageMetadata(
        identity=PackageIdentity(
            name="controlled-provenance-package",
            normalized_name="controlled-provenance-package",
            version=audited_version,
        ),
        metadata_available=True,
    )

    def fake_fetch_pypi_project(package_name: str) -> dict:
        return {
            "info": {
                "version": "9.9.9",
                "project_urls": {"Source": f"https://example.test/{package_name}/source"},
            },
            "releases": {
                audited_version: [
                    {
                        "filename": f"{package_name}-{audited_version}.tar.gz",
                        "packagetype": "sdist",
                        "upload_time_iso_8601": "2026-01-02T03:04:05Z",
                    }
                ]
            },
        }

    monkeypatch.setattr("pkgwhy.cli.fetch_pypi_project", fake_fetch_pypi_project)
    monkeypatch.setattr("pkgwhy.cli.list_installed_packages", lambda: [installed])

    result = runner.invoke(app, ["audit", "--limit", "1", "--json", "--pypi"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["provenance_sources"] == ["pypi_json"]
    provenance = data["packages"][0]["provenance"]
    assert provenance["metadata_source"] == "pypi_json"
    assert provenance["version"] == audited_version
    assert provenance["source_distribution_status"] == "present"
    assert provenance["trusted_publishing_status"] == "unknown"
    assert provenance["attestation_status"] == "not_implemented"


def test_audit_json_includes_top_level_lookup_warnings(monkeypatch) -> None:
    installed = PackageMetadata(
        identity=PackageIdentity(
            name="controlled-warning-package",
            normalized_name="controlled-warning-package",
            version="1.0.0",
        ),
        metadata_available=True,
    )

    def fake_query_osv_cached(package_name: str, version: str | None, **_: object) -> OSVLookupResult:
        return OSVLookupResult(
            records=[],
            cache_status="unavailable",
            warnings=(f"Controlled OSV.dev warning for {package_name} {version}.",),
        )

    monkeypatch.setattr("pkgwhy.cli.list_installed_packages", lambda: [installed])
    monkeypatch.setattr("pkgwhy.cli.query_osv_cached", fake_query_osv_cached)

    result = runner.invoke(app, ["audit", "--limit", "1", "--json", "--osv"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["warnings"] == [
        "Controlled OSV.dev warning for controlled-warning-package 1.0.0.",
        "OSV.dev lookup unavailable for controlled-warning-package; no vulnerability result was inferred.",
    ]


def test_audit_markdown_escapes_table_pipes() -> None:
    judgement = PackageJudgement(
        package="<demo>|package",
        version="<1>|2",
        decision=AgentDecision.ALLOW,
        risk_level=RiskLevel.LOW,
        confidence=Confidence.HIGH,
        summary="demo",
        source_availability=SourceAvailability.INSTALLED_SOURCE_PRESENT,
        installed_size_bytes=1,
        recommendation="ok",
    )

    rendered = render_audit_markdown([judgement])

    assert "&lt;demo&gt;\\|package" in rendered
    assert "&lt;1&gt;\\|2" in rendered


def test_audit_markdown_escapes_newlines_and_backslashes() -> None:
    judgement = PackageJudgement(
        package="demo\npackage",
        version=r"1\2",
        decision=AgentDecision.ALLOW,
        risk_level=RiskLevel.LOW,
        confidence=Confidence.HIGH,
        summary="demo",
        source_availability=SourceAvailability.INSTALLED_SOURCE_PRESENT,
        installed_size_bytes=1,
        recommendation="ok",
    )

    rendered = render_audit_markdown([judgement])

    assert "demo package" in rendered
    assert r"1\\2" in rendered
    assert "demo\npackage" not in rendered
    assert len([line for line in rendered.splitlines() if line.startswith("| ")]) == 3


def test_audit_markdown_includes_audit_warnings() -> None:
    judgement = PackageJudgement(
        package="demo",
        version="1.0",
        decision=AgentDecision.ALLOW,
        risk_level=RiskLevel.LOW,
        confidence=Confidence.HIGH,
        summary="demo",
        source_availability=SourceAvailability.INSTALLED_SOURCE_PRESENT,
        installed_size_bytes=1,
        recommendation="ok",
    )

    rendered = render_audit_markdown([judgement], warnings=["OSV <unavailable>\nno result inferred"])

    assert "## Warnings" in rendered
    assert "- OSV &lt;unavailable&gt; no result inferred" in rendered

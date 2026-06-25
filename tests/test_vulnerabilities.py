import json

from typer.testing import CliRunner

from pkgwhy.agent.judge import judge_installed_package
from pkgwhy.cli import app
from pkgwhy.metadata.installed import list_installed_packages
from pkgwhy.vulnerabilities.matching import match_vulnerabilities
from pkgwhy.vulnerabilities.osv import parse_osv_payload

runner = CliRunner()


def test_parse_osv_payload_extracts_python_advisory_records() -> None:
    records = parse_osv_payload(_osv_payload("Demo-Pkg", ["1.2.3"]))

    assert len(records) == 1
    assert records[0].id == "TEST-VULN-0001"
    assert records[0].package_name == "demo-pkg"
    assert records[0].fixed_versions == ["2.0.0"]
    assert records[0].source == "OSV.dev"


def test_version_matching_is_conservative_for_fixed_ranges() -> None:
    records = parse_osv_payload(_osv_payload("demo-pkg", []))

    assert match_vulnerabilities("demo-pkg", "1.5.0", records)
    assert not match_vulnerabilities("demo-pkg", "2.0.0", records)
    assert not match_vulnerabilities("other-pkg", "1.5.0", records)
    assert not match_vulnerabilities("demo-pkg", "not-a-version", records)


def test_judgement_includes_known_vulnerability_rule_evidence() -> None:
    package = list_installed_packages()[0]
    records = parse_osv_payload(_osv_payload(package.identity.name, [package.identity.version or "0"]))
    matches = match_vulnerabilities(package.identity.name, package.identity.version, records)

    judgement = judge_installed_package(package.identity.name, known_vulnerabilities=matches)

    assert judgement.known_vulnerabilities
    assert judgement.risk_level in {"high", "critical"}
    assert any(rule.rule_id == "PKGWHY-VULN-001" for rule in judgement.risk_rules)
    assert any("Known vulnerability match" in warning for warning in judgement.warnings)


def test_audit_json_includes_fixture_vulnerability_matches(tmp_path) -> None:
    package = list_installed_packages()[0]
    vulnerability_file = tmp_path / "osv.json"
    vulnerability_file.write_text(
        json.dumps(_osv_payload(package.identity.name, [package.identity.version or "0"])),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["audit", "--limit", "1", "--json", "--vulnerability-file", str(vulnerability_file)])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["vulnerability_match_count"] == 1
    assert data["packages"][0]["known_vulnerabilities"][0]["vulnerability_id"] == "TEST-VULN-0001"
    assert data["packages"][0]["risk_model_version"] == "pkgwhy.risk_model.v1"


def _osv_payload(package: str, affected_versions: list[str]) -> dict:
    return {
        "vulns": [
            {
                "id": "TEST-VULN-0001",
                "aliases": ["CVE-0000-0000"],
                "summary": "Controlled test advisory for parser and matcher coverage.",
                "affected": [
                    {
                        "package": {"name": package, "ecosystem": "PyPI"},
                        "versions": affected_versions,
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "1.0.0"},
                                    {"fixed": "2.0.0"},
                                ],
                            }
                        ],
                    }
                ],
                "severity": [{"type": "CVSS_V3", "score": "HIGH"}],
                "references": [{"type": "WEB", "url": "https://osv.dev/vulnerability/TEST-VULN-0001"}],
            }
        ]
    }

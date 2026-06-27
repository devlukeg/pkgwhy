import json

import pytest
from typer.testing import CliRunner

from pkgwhy.agent.judge import judge_installed_package
from pkgwhy.cli import _dedupe_vulnerability_matches, app
from pkgwhy.core.models import PackageMetadata, VulnerabilityMatch
from pkgwhy.metadata.installed import list_installed_packages
from pkgwhy.vulnerabilities.matching import match_vulnerabilities
from pkgwhy.vulnerabilities.osv import OSVClientError, parse_osv_payload, query_osv_cached

runner = CliRunner()


def test_parse_osv_payload_extracts_python_advisory_records() -> None:
    records = parse_osv_payload(_osv_payload("Demo-Pkg", ["1.2.3"]))

    assert len(records) == 1
    assert records[0].id == "TEST-VULN-0001"
    assert records[0].package_name == "demo-pkg"
    assert records[0].fixed_versions == ["2.0.0"]
    assert records[0].source == "OSV.dev"


def test_parse_osv_payload_accepts_single_advisory_object() -> None:
    payload = _osv_payload("Demo-Pkg", ["1.2.3"])["vulns"][0]

    records = parse_osv_payload(payload)

    assert len(records) == 1
    assert records[0].id == "TEST-VULN-0001"


def test_version_matching_is_conservative_for_fixed_ranges() -> None:
    records = parse_osv_payload(_osv_payload("demo-pkg", []))

    assert match_vulnerabilities("demo-pkg", "1.5.0", records)
    assert not match_vulnerabilities("demo-pkg", "2.0.0", records)
    assert not match_vulnerabilities("other-pkg", "1.5.0", records)
    assert not match_vulnerabilities("demo-pkg", "not-a-version", records)


def test_version_matching_ignores_non_version_ranges() -> None:
    payload = _osv_payload("demo-pkg", [])
    payload["vulns"][0]["affected"][0]["ranges"][0]["type"] = "GIT"
    records = parse_osv_payload(payload)

    assert not match_vulnerabilities("demo-pkg", "1.5.0", records)


def test_version_matching_ignores_semver_ranges_without_pep440_claims() -> None:
    payload = _osv_payload("demo-pkg", [])
    payload["vulns"][0]["affected"][0]["ranges"][0]["type"] = "SEMVER"
    records = parse_osv_payload(payload)

    assert not match_vulnerabilities("demo-pkg", "1.5.0", records)


def test_version_matching_treats_osv_limit_as_upper_bound_not_fixed_version() -> None:
    payload = _osv_payload("demo-pkg", [])
    payload["vulns"][0]["affected"][0]["ranges"][0]["events"] = [
        {"introduced": "1.0.0"},
        {"limit": "2.0.0"},
    ]
    records = parse_osv_payload(payload)

    assert match_vulnerabilities("demo-pkg", "1.5.0", records)
    assert not match_vulnerabilities("demo-pkg", "2.0.0", records)
    assert records[0].fixed_versions == []


def test_version_matching_supports_limit_only_osv_ranges() -> None:
    payload = _osv_payload("demo-pkg", [])
    payload["vulns"][0]["affected"][0]["ranges"][0]["events"] = [
        {"limit": "2.0.0"},
    ]
    records = parse_osv_payload(payload)

    assert match_vulnerabilities("demo-pkg", "1.5.0", records)
    assert not match_vulnerabilities("demo-pkg", "2.0.0", records)


def test_version_matching_deduplicates_and_compares_explicit_versions_semantically() -> None:
    payload = _osv_payload("demo-pkg", ["1.0"])
    records = parse_osv_payload({"vulns": payload["vulns"] + payload["vulns"]})

    matches = match_vulnerabilities("demo-pkg", "1.0.0", records)

    assert len(matches) == 1
    assert matches[0].vulnerability_id == "TEST-VULN-0001"


def test_cli_vulnerability_dedupe_keeps_stronger_match() -> None:
    weak = VulnerabilityMatch(
        vulnerability_id="TEST-VULN-0001",
        package="demo-pkg",
        version="1.0.0",
        severity=["LOW"],
        source="fixture",
        evidence=["weak match"],
    )
    strong = VulnerabilityMatch(
        vulnerability_id="TEST-VULN-0001",
        package="demo-pkg",
        version="1.0.0",
        severity=["HIGH"],
        fixed_versions=["2.0.0"],
        references=["https://example.invalid/advisory"],
        source="fixture",
        source_url="https://example.invalid/advisory",
        evidence=["strong match", "range match"],
    )

    matches = _dedupe_vulnerability_matches([weak, strong])

    assert matches == [strong]


def test_query_osv_cached_uses_stale_cache_when_online_lookup_fails(tmp_path, monkeypatch) -> None:
    payload = _osv_payload("demo-pkg", ["1.2.3"])
    monkeypatch.setattr("pkgwhy.vulnerabilities.osv._fetch_osv_payload", lambda *_, **__: payload)

    fresh = query_osv_cached("demo-pkg", "1.2.3", cache_dir=tmp_path)

    assert fresh.cache_status == "fresh"
    assert fresh.cache_path is not None
    assert fresh.cache_path.exists()
    assert fresh.records[0].source == "OSV.dev"

    def fail_fetch(*_: object, **__: object) -> dict:
        raise OSVClientError("network unavailable")

    monkeypatch.setattr("pkgwhy.vulnerabilities.osv._fetch_osv_payload", fail_fetch)

    stale = query_osv_cached("demo-pkg", "1.2.3", cache_dir=tmp_path)

    assert stale.cache_status == "stale_cache"
    assert stale.records[0].id == "TEST-VULN-0001"
    assert any("Cached advisory data may be stale" in warning for warning in stale.warnings)
    assert all(str(tmp_path) not in warning for warning in stale.warnings)


def test_query_osv_cached_rejects_mismatched_cache_document(tmp_path, monkeypatch) -> None:
    payload = _osv_payload("demo-pkg", ["1.2.3"])
    monkeypatch.setattr("pkgwhy.vulnerabilities.osv._fetch_osv_payload", lambda *_, **__: payload)
    fresh = query_osv_cached("demo-pkg", "1.2.3", cache_dir=tmp_path)
    assert fresh.cache_path is not None
    cache_path = fresh.cache_path
    cached = json.loads(cache_path.read_text(encoding="utf-8"))
    cached["package"] = "other-pkg"
    cache_path.write_text(json.dumps(cached), encoding="utf-8")

    def fail_fetch(*_: object, **__: object) -> dict:
        raise OSVClientError("network unavailable")

    monkeypatch.setattr("pkgwhy.vulnerabilities.osv._fetch_osv_payload", fail_fetch)

    result = query_osv_cached("demo-pkg", "1.2.3", cache_dir=tmp_path)

    assert result.cache_status == "unavailable"
    assert result.records == []


def test_query_osv_cached_reports_unavailable_without_fabricating_records(tmp_path, monkeypatch) -> None:
    def fail_fetch(*_: object, **__: object) -> dict:
        raise OSVClientError("network unavailable")

    monkeypatch.setattr("pkgwhy.vulnerabilities.osv._fetch_osv_payload", fail_fetch)

    result = query_osv_cached("demo-pkg", "1.2.3", cache_dir=tmp_path)

    assert result.cache_status == "unavailable"
    assert result.records == []
    assert any("Missing vulnerability matches are not proof of safety" in warning for warning in result.warnings)


def test_judgement_includes_known_vulnerability_rule_evidence() -> None:
    package = _first_installed_package()
    records = parse_osv_payload(_osv_payload(package.identity.name, [package.identity.version or "0"]))
    matches = match_vulnerabilities(package.identity.name, package.identity.version, records)

    judgement = judge_installed_package(package.identity.name, known_vulnerabilities=matches)

    assert judgement.known_vulnerabilities
    assert judgement.risk_level in {"high", "critical"}
    assert any(rule.rule_id == "PKGWHY-VULN-001" for rule in judgement.risk_rules)
    assert any("Known vulnerability match" in warning for warning in judgement.warnings)


def test_audit_json_includes_fixture_vulnerability_matches(tmp_path) -> None:
    package = _first_installed_package()
    vulnerability_file = tmp_path / "osv.json"
    vulnerability_file.write_text(
        json.dumps(_osv_payload(package.identity.name, [package.identity.version or "0"])),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["audit", "--limit", "1", "--json", "--vulnerability-file", str(vulnerability_file)])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["vulnerability_match_count"] == 1
    assert data["vulnerability_sources"] == ["OSV.dev"]
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


def _first_installed_package() -> PackageMetadata:
    packages = list_installed_packages()
    if not packages:
        pytest.skip("No installed packages discovered in active test environment.")
    return packages[0]

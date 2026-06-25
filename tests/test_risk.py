from pkgwhy.core.constants import CAPABILITY_EXPOSURE_NOTE
from pkgwhy.core.models import PackageIdentity, PackageInspection, PackageMetadata, PackageSize, VulnerabilityMatch
from pkgwhy.risk.scoring import judge_inspection


def test_judge_inspection_uses_conservative_warning_for_unknown_source() -> None:
    inspection = PackageInspection(
        metadata=PackageMetadata(
            identity=PackageIdentity(name="example", normalized_name="example", version="0.1.0"),
            summary="Example package.",
            license=None,
        ),
        source_availability="source_availability_unknown",
        readability="not_enough_source_available",
        size=PackageSize(total_bytes=10, file_count=1),
        evidence=["metadata checked"],
    )

    judgement = judge_inspection(inspection)

    assert judgement.risk_level == "medium"
    assert judgement.decision == "allow_with_caution"
    assert "Source availability is unknown from installed files." in judgement.warnings
    assert judgement.risk_model_version == "pkgwhy.risk_model.v1"
    assert any(rule.rule_id == "PKGWHY-RISK-002" for rule in judgement.risk_rules)
    assert judgement.capability_exposure_note == CAPABILITY_EXPOSURE_NOTE


def test_judge_inspection_warns_on_static_capability_signals_without_overclaiming() -> None:
    inspection = PackageInspection(
        metadata=PackageMetadata(
            identity=PackageIdentity(name="example", normalized_name="example", version="0.1.0"),
            summary="Example package.",
            license="MIT",
        ),
        source_availability="installed_source_present",
        readability="readable",
        size=PackageSize(total_bytes=10, file_count=1),
        detected_capabilities=["Subprocess or shell execution signals"],
        evidence=["static AST checked"],
    )

    judgement = judge_inspection(inspection)

    assert judgement.risk_level == "medium"
    assert judgement.decision == "allow_with_caution"
    assert any("This is not proof of unsafe behavior" in warning for warning in judgement.warnings)
    assert any(rule.rule_id == "PKGWHY-RISK-005" for rule in judgement.risk_rules)


def test_judge_inspection_warns_on_static_file_signals_without_overclaiming() -> None:
    inspection = PackageInspection(
        metadata=PackageMetadata(
            identity=PackageIdentity(name="example", normalized_name="example", version="0.1.0"),
            summary="Example package.",
            license="MIT",
        ),
        source_availability="installed_source_present",
        readability="possibly_obfuscated",
        size=PackageSize(total_bytes=10, file_count=1),
        detected_capabilities=[
            "JavaScript dynamic code execution signals",
            "Shell script files present",
            "WASM binary code present",
        ],
        evidence=["static file signals checked"],
    )

    judgement = judge_inspection(inspection)

    assert judgement.risk_level == "medium"
    assert judgement.decision == "allow_with_caution"
    assert any("JavaScript dynamic code execution signals" in warning for warning in judgement.warnings)
    assert any("Shell script files present" in warning for warning in judgement.warnings)
    assert any("WASM binary code present" in warning for warning in judgement.warnings)
    assert all("malicious" not in warning.lower() for warning in judgement.warnings)
    assert {rule.rule_id for rule in judgement.risk_rules} == {"PKGWHY-RISK-005"}


def test_judge_inspection_does_not_downgrade_vulnerability_risk_when_files_are_missing() -> None:
    inspection = PackageInspection(
        metadata=PackageMetadata(
            identity=PackageIdentity(name="example", normalized_name="example", version="1.0.0"),
            summary="Example package.",
            license="MIT",
        ),
        source_availability="installed_metadata_only",
        readability="not_enough_source_available",
        size=PackageSize(total_bytes=0, file_count=0),
        evidence=["metadata checked"],
    )
    vulnerability = VulnerabilityMatch(
        vulnerability_id="TEST-VULN-CRITICAL",
        package="example",
        version="1.0.0",
        severity=["CRITICAL"],
        source="controlled test fixture",
        evidence=["Controlled test advisory matched."],
    )

    judgement = judge_inspection(inspection, known_vulnerabilities=[vulnerability])

    assert judgement.risk_level == "critical"
    assert judgement.decision == "block"
    assert any(rule.rule_id == "PKGWHY-RISK-006" for rule in judgement.risk_rules)
    assert any(rule.rule_id == "PKGWHY-VULN-001" for rule in judgement.risk_rules)

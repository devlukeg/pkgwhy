from pkgwhy.core.constants import CAPABILITY_EXPOSURE_NOTE
from pkgwhy.core.models import PackageIdentity, PackageInspection, PackageMetadata, PackageSize
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

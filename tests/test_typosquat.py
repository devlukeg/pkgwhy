from typer.testing import CliRunner

from pkgwhy.cli import app
from pkgwhy.core.models import PackageIdentity, PackageInspection, PackageMetadata, PackageSize
from pkgwhy.risk.scoring import judge_inspection
from pkgwhy.typosquat.detector import detect_typosquat, detect_typosquats

runner = CliRunner()
MIN_EXPECTED_SIMILARITY = 0.72


def test_detect_typosquat_examples() -> None:
    examples = {
        "pnadas": "pandas",
        "reqeusts": "requests",
        "numppy": "numpy",
        "djagno": "django",
        "sklean": "scikit-learn",
    }

    for package, target in examples.items():
        candidate = detect_typosquat(package)

        assert candidate is not None
        assert candidate.is_possible_typosquat is True
        assert candidate.possible_target == target
        assert candidate.similarity >= MIN_EXPECTED_SIMILARITY
        assert candidate.signals


def test_detect_typosquat_false_positive_guards_for_known_families() -> None:
    guarded = ["django-debug-toolbar", "pytest-cov", "pandas-stubs", "types-requests"]

    assert all(detect_typosquat(package) is None for package in guarded)


def test_detect_typosquats_sorts_strongest_signals_first() -> None:
    candidates = detect_typosquats(["requests", "reqeusts", "pnadas"])

    assert candidates == sorted(candidates, key=lambda item: (-item.similarity, -len(item.signals), item.package))
    assert {candidate.package for candidate in candidates} == {"reqeusts", "pnadas"}


def test_typos_command_reports_package_similarity() -> None:
    result = runner.invoke(app, ["typos", "reqeusts"])

    assert result.exit_code == 0
    assert "reqeusts" in result.output
    assert "requests" in result.output
    assert "Possible typosquatting signals" in result.output


def test_judge_inspection_integrates_typosquat_warning() -> None:
    inspection = PackageInspection(
        metadata=PackageMetadata(
            identity=PackageIdentity(name="reqeusts", normalized_name="reqeusts", version="1.0.0"),
            summary="Example package.",
            license="MIT",
        ),
        source_availability="installed_source_present",
        readability="readable",
        size=PackageSize(total_bytes=10, file_count=1),
        evidence=["metadata checked"],
    )

    judgement = judge_inspection(inspection)

    assert judgement.risk_level == "medium"
    assert judgement.decision == "allow_with_caution"
    assert any("Possible typosquatting risk" in warning for warning in judgement.warnings)
    assert all("malicious" not in warning.lower() for warning in judgement.warnings)

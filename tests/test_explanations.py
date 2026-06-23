from pkgwhy.core.models import PackageIdentity, PackageMetadata
from pkgwhy.explanations.explain import explain_package


def test_explain_package_uses_builtin_database() -> None:
    metadata = PackageMetadata(identity=PackageIdentity(name="Typer", normalized_name="typer", version="1.0"))

    explanation = explain_package(metadata, "typer", "direct")

    assert explanation.package == "typer"
    assert explanation.version == "1.0"
    assert explanation.dependency_status == "direct"
    assert explanation.confidence == "high"
    assert "built-in pkgwhy explanation database" in explanation.sources_used


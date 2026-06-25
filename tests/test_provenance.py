from pkgwhy.core.models import PackageIdentity, PackageMetadata, ProjectUrls
from pkgwhy.metadata.pypi import provenance_from_pypi_payload
from pkgwhy.provenance.installed import assess_installed_provenance


def test_installed_provenance_marks_unimplemented_trust_checks() -> None:
    metadata = PackageMetadata(
        identity=PackageIdentity(name="example", normalized_name="example", version="0.1.0"),
        project_urls=ProjectUrls(repository="https://example.test/repo", raw={"Source": "https://example.test/repo"}),
    )

    provenance = assess_installed_provenance(metadata)

    assert provenance.repository_url == "https://example.test/repo"
    assert provenance.trusted_publishing_status == "unknown"
    assert provenance.attestation_status == "not_implemented"
    assert provenance.source_distribution_status == "unknown"
    assert any("Attestation verification is not implemented" in warning for warning in provenance.warnings)


def test_pypi_provenance_payload_extracts_release_activity_without_attestation_claims() -> None:
    provenance = provenance_from_pypi_payload(
        "Example",
        {
            "info": {
                "version": "1.0.0",
                "project_urls": {
                    "Source": "https://example.test/source",
                    "Documentation": "https://example.test/docs",
                },
            },
            "releases": {
                "1.0.0": [{"upload_time_iso_8601": "2026-01-02T03:04:05Z"}],
                "0.9.0": [{"upload_time_iso_8601": "2025-12-31T00:00:00Z"}],
            },
        },
    )

    assert provenance.metadata_source == "pypi_json"
    assert provenance.repository_url == "https://example.test/source"
    assert provenance.documentation_url == "https://example.test/docs"
    assert provenance.release_activity_status == "latest_release_upload:2026-01-02"
    assert provenance.trusted_publishing_status == "unknown"
    assert provenance.attestation_status == "not_implemented"

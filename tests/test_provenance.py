from pkgwhy.core.models import PackageIdentity, PackageMetadata, ProjectUrls
from pkgwhy.metadata.pypi import provenance_from_pypi_payload
from pkgwhy.provenance.installed import assess_installed_provenance


def test_installed_provenance_marks_unimplemented_trust_checks() -> None:
    metadata = PackageMetadata(
        identity=PackageIdentity(name="Example", normalized_name="example", version="0.1.0"),
        project_urls=ProjectUrls(repository="https://example.test/repo", raw={"Source": "https://example.test/repo"}),
    )

    provenance = assess_installed_provenance(metadata)

    assert provenance.package == "example"
    assert provenance.repository_url == "https://example.test/repo"
    assert provenance.metadata_source == "installed_distribution_metadata"
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
                "1.0.0": [
                    {
                        "filename": "example-1.0.0.tar.gz",
                        "packagetype": "sdist",
                        "upload_time_iso_8601": "2026-01-02T03:04:05Z",
                    }
                ],
                "0.9.0": [{"upload_time_iso_8601": "2025-12-31T00:00:00Z"}],
            },
        },
    )

    assert provenance.metadata_source == "pypi_json"
    assert provenance.repository_url == "https://example.test/source"
    assert provenance.documentation_url == "https://example.test/docs"
    assert provenance.release_activity_status == "latest_release_upload:2026-01-02"
    assert provenance.source_distribution_status == "present"
    assert provenance.trusted_publishing_status == "unknown"
    assert provenance.attestation_status == "not_implemented"


def test_pypi_provenance_reports_missing_source_distribution_without_attestation_claims() -> None:
    provenance = provenance_from_pypi_payload(
        "Example",
        {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "filename": "example-1.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "upload_time_iso_8601": "2026-01-02T03:04:05Z",
                    }
                ],
            },
        },
    )

    assert provenance.source_distribution_status == "not_found"
    assert provenance.trusted_publishing_status == "unknown"
    assert provenance.attestation_status == "not_implemented"
    assert any("did not list a source distribution" in warning for warning in provenance.warnings)


def test_pypi_provenance_uses_audited_version_for_source_distribution_status() -> None:
    provenance = provenance_from_pypi_payload(
        "Example",
        {
            "info": {"version": "2.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "filename": "example-1.0.0.tar.gz",
                        "packagetype": "sdist",
                        "upload_time_iso_8601": "2026-01-02T03:04:05Z",
                    }
                ],
                "2.0.0": [
                    {
                        "filename": "example-2.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "upload_time_iso_8601": "2026-02-03T04:05:06Z",
                    }
                ],
            },
        },
        audited_version="1.0.0",
    )

    assert provenance.version == "1.0.0"
    assert provenance.source_distribution_status == "present"
    assert provenance.release_activity_status == "audited_release_upload:2026-01-02"


def test_pypi_provenance_matches_pep440_equivalent_audited_version() -> None:
    provenance = provenance_from_pypi_payload(
        "Example",
        {
            "info": {"version": "2.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "filename": "example-1.0.0.tar.gz",
                        "packagetype": "sdist",
                        "upload_time_iso_8601": "2026-01-02T03:04:05Z",
                    }
                ],
            },
        },
        audited_version="1.0",
    )

    assert provenance.version == "1.0"
    assert provenance.source_distribution_status == "present"
    assert provenance.release_activity_status == "audited_release_upload:2026-01-02"


def test_pypi_provenance_keeps_missing_audited_version_unknown() -> None:
    provenance = provenance_from_pypi_payload(
        "Example",
        {
            "info": {"version": "2.0.0"},
            "releases": {
                "2.0.0": [
                    {
                        "filename": "example-2.0.0.tar.gz",
                        "packagetype": "sdist",
                        "upload_time_iso_8601": "2026-02-03T04:05:06Z",
                    }
                ],
            },
        },
        audited_version="1.0.0",
    )

    assert provenance.version == "1.0.0"
    assert provenance.source_distribution_status == "unknown"
    assert provenance.release_activity_status == "unknown"
    assert any("audited version 1.0.0" in warning for warning in provenance.warnings)


def test_pypi_provenance_ignores_empty_url_values() -> None:
    provenance = provenance_from_pypi_payload(
        "Example",
        {
            "info": {
                "home_page": " ",
                "project_urls": {
                    "Source": "",
                    "Documentation": "   ",
                },
            },
            "releases": {},
        },
    )

    assert provenance.repository_url is None
    assert provenance.documentation_url is None
    assert provenance.homepage_url is None

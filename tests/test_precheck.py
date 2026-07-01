import hashlib
import json
from pathlib import Path
import tarfile
import zipfile

from pydantic import ValidationError
import pytest
from typer.testing import CliRunner

from pkgwhy.cli import app
from pkgwhy.core.models import PrecheckArtifactSummary, PrecheckBatchResult, PreInstallPackagePrecheckResult
from pkgwhy.metadata.installed import get_installed_package
from pkgwhy.precheck import (
    PrecheckTargetError,
    _extract_tar,
    build_package_precheck,
    build_requirements_precheck,
    parse_precheck_target,
)

runner = CliRunner()


def test_parse_precheck_target_preserves_exact_version() -> None:
    parsed = parse_precheck_target("Typer==0.12.5")

    assert parsed.package == "Typer"
    assert parsed.normalized_package == "typer"
    assert parsed.specifier == "==0.12.5"
    assert parsed.exact_version == "0.12.5"


def test_parse_precheck_target_rejects_direct_references() -> None:
    with pytest.raises(PrecheckTargetError):
        parse_precheck_target("demo-precheck @ https://example.invalid/demo-precheck.whl")


def test_precheck_missing_package_offline_does_not_install_or_fetch() -> None:
    package_name = "definitely-not-installed-pkgwhy-precheck-0cc0d"
    assert get_installed_package(package_name) is None

    result = build_package_precheck(package_name)

    PreInstallPackagePrecheckResult.model_validate(result.model_dump(mode="json"))
    assert result.schema_version == "pkgwhy.precheck.v1"
    assert result.package == package_name
    assert result.lookup_status == "offline_metadata_unavailable"
    assert result.network_requested is False
    assert result.artifacts_downloaded is False
    assert result.risk_level == "unknown"
    assert result.decision == "block"
    assert result.exit_code == 2
    assert result.vulnerability_summary.status == "not_requested"
    assert any("Did not install, import, or execute" in item for item in result.evidence)
    assert get_installed_package(package_name) is None


def test_precheck_schema_version_is_fixed() -> None:
    package_name = "definitely-not-installed-pkgwhy-precheck-schema-1"
    result = build_package_precheck(package_name)
    data = result.model_dump(mode="json")
    data["schema_version"] = "wrong.version"

    with pytest.raises(ValidationError):
        PreInstallPackagePrecheckResult.model_validate(data)


def test_precheck_artifact_counters_reject_negative_values() -> None:
    with pytest.raises(ValidationError):
        PrecheckArtifactSummary(size_bytes=-1)
    with pytest.raises(ValidationError):
        PrecheckArtifactSummary(extracted_file_count=-1)


def test_precheck_batch_package_count_must_match_results() -> None:
    result = build_package_precheck("definitely-not-installed-pkgwhy-precheck-count-1")
    data = {
        "schema_version": "pkgwhy.precheck_batch.v1",
        "target_type": "requirements",
        "source": "requirements.txt",
        "package_count": 2,
        "decision": result.decision,
        "exit_code": result.exit_code,
        "risk_level": result.risk_level,
        "confidence": result.confidence,
        "results": [result.model_dump(mode="json")],
    }

    with pytest.raises(ValidationError):
        PrecheckBatchResult.model_validate(data)


def test_precheck_uses_mocked_pypi_metadata_without_artifact_download(monkeypatch) -> None:
    payload = {
        "info": {
            "name": "demo-precheck",
            "version": "1.2.3",
            "summary": "Demo package",
            "license": "MIT",
            "project_urls": {"Source": "https://example.invalid/demo"},
        },
        "releases": {"1.2.3": [{"packagetype": "sdist", "upload_time_iso_8601": "2026-01-01T00:00:00"}]},
    }
    monkeypatch.setattr("pkgwhy.precheck.fetch_pypi_project", lambda package: payload)

    result = build_package_precheck("demo-precheck==1.2.3", pypi=True)

    assert result.metadata_source == "pypi_json"
    assert result.lookup_status == "metadata_found"
    assert result.version == "1.2.3"
    assert result.network_requested is True
    assert result.artifacts_downloaded is False
    assert result.provenance_summary.status == "pypi_json"
    assert result.static_summary.status == "not_requested"
    assert "Metadata-only precheck cannot prove package contents are safe." in result.warnings


def test_precheck_rejects_missing_exact_pypi_release(monkeypatch) -> None:
    payload = {
        "info": {
            "name": "demo-precheck",
            "version": "2.0.0",
            "summary": "Demo package",
            "license": "MIT",
        },
        "releases": {"2.0.0": [{"packagetype": "sdist"}]},
    }
    monkeypatch.setattr("pkgwhy.precheck.fetch_pypi_project", lambda package: payload)

    result = build_package_precheck("demo-precheck==1.0.0", pypi=True)

    assert result.lookup_status == "requested_release_unavailable"
    assert result.version == "1.0.0"
    assert result.exit_code == 2
    assert any("did not list requested release version 1.0.0" in warning for warning in result.warnings)


def test_precheck_pypi_non_exact_specifier_selects_matching_release(monkeypatch) -> None:
    payload = {
        "info": {
            "name": "demo-precheck",
            "version": "2.0.0",
            "summary": "Demo package",
            "license": "MIT",
        },
        "releases": {
            "1.0.0": [{"packagetype": "sdist"}],
            "1.5.0": [{"packagetype": "sdist"}],
            "2.0.0": [{"packagetype": "sdist"}],
        },
    }
    monkeypatch.setattr("pkgwhy.precheck.fetch_pypi_project", lambda package: payload)

    result = build_package_precheck("demo-precheck>=1,<2", pypi=True)

    assert result.lookup_status == "metadata_found"
    assert result.version == "1.5.0"
    assert result.summary == "No installed summary is available for this package."
    assert result.provenance_summary.status == "pypi_json"
    assert any("version-specific summary" in warning for warning in result.warnings)


def test_precheck_pypi_non_exact_specifier_requires_matching_release(monkeypatch) -> None:
    payload = {
        "info": {
            "name": "demo-precheck",
            "version": "2.0.0",
            "summary": "Demo package",
            "license": "MIT",
        },
        "releases": {"2.0.0": [{"packagetype": "sdist"}]},
    }
    monkeypatch.setattr("pkgwhy.precheck.fetch_pypi_project", lambda package: payload)

    result = build_package_precheck("demo-precheck<2", pypi=True)

    assert result.lookup_status == "requested_release_unavailable"
    assert result.version is None
    assert any("did not list a release satisfying <2" in warning for warning in result.warnings)


def test_precheck_pypi_bare_target_prefers_stable_release(monkeypatch) -> None:
    payload = {
        "info": {
            "name": "demo-precheck",
            "version": "2.0.0a1",
            "summary": "Demo package",
            "license": "MIT",
        },
        "releases": {
            "1.0.0": [{"packagetype": "sdist"}],
            "2.0.0a1": [{"packagetype": "sdist"}],
        },
    }
    monkeypatch.setattr("pkgwhy.precheck.fetch_pypi_project", lambda package: payload)

    result = build_package_precheck("demo-precheck", pypi=True)

    assert result.version == "1.0.0"


def test_precheck_cli_json_for_installed_package() -> None:
    assert get_installed_package("typer") is not None

    result = runner.invoke(app, ["precheck", "typer", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    PreInstallPackagePrecheckResult.model_validate(data)
    assert data["schema_version"] == "pkgwhy.precheck.v1"
    assert data["command"] == "pkgwhy precheck"
    assert data["target"] == "typer"
    assert data["exit_code_meaning"] == "blocked by policy or risk decision"
    assert data["recommended_next_action"]
    assert data["evidence_summary"]["evidence_count"] == len(data["evidence"])
    assert data["source_freshness"] == "local_installed_distribution_metadata"
    assert data["package"] == "typer"
    assert data["metadata_source"] == "installed_distribution_metadata"
    assert data["artifacts_downloaded"] is False
    assert data["package_judgement"]["schema_version"] == "pkgwhy.package_judgement.v1"


def test_precheck_cli_accepts_vulnerability_file(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vulns.json"
    vuln_file.write_text(
        """
{
  "vulns": [
    {
      "id": "GHSA-demo",
      "affected": [
        {
          "package": {"ecosystem": "PyPI", "name": "demo-precheck-vuln"},
          "versions": ["1.0.0"]
        }
      ]
    }
  ]
}
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["precheck", "demo-precheck-vuln==1.0.0", "--vulnerability-file", str(vuln_file), "--json"],
    )

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["vulnerability_summary"]["status"] == "matches_found"
    assert data["vulnerability_summary"]["match_count"] == 1


def test_precheck_cli_rejects_malformed_vulnerability_file(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vulns.json"
    vuln_file.write_text("{not-json", encoding="utf-8")

    result = runner.invoke(
        app,
        ["precheck", "demo-precheck-vuln==1.0.0", "--vulnerability-file", str(vuln_file), "--json"],
    )

    assert result.exit_code == 3
    data = json.loads(result.output)
    assert data["message"].startswith(f"could not load vulnerability file {vuln_file}:")
    assert "Could not read vulnerability data" in data["message"]
    assert str(vuln_file) in data["message"]
    data["message"] = "<parser-specific message>"
    assert data == {
        "schema_version": "pkgwhy.error.v1",
        "command": "pkgwhy precheck",
        "target": "demo-precheck-vuln==1.0.0",
        "target_type": "package",
        "error_type": "PrecheckFileError",
        "message": "<parser-specific message>",
        "exit_code": 3,
        "exit_code_meaning": "tool, configuration, or user input error",
        "suggested_fix": "Pass a valid package requirement such as 'requests' or 'requests==2.32.0'.",
    }


def test_precheck_cli_requirements_file_json(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "typer\n# ignored\n-r other.txt\ndefinitely-not-installed-pkgwhy-precheck-req-1==1.0.0\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["precheck", "-r", str(requirements), "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    PrecheckBatchResult.model_validate(data)
    assert data["schema_version"] == "pkgwhy.precheck_batch.v1"
    assert data["command"] == "pkgwhy precheck"
    assert data["target"] == str(requirements)
    assert data["exit_code_meaning"] == "blocked by policy or risk decision"
    assert data["recommended_next_action"]
    assert data["evidence_summary"]["evidence_count"] >= len(data["evidence"])
    assert data["source_freshness"] == "dependency_file_snapshot"
    assert data["target_type"] == "requirements"
    assert data["package_count"] == 2
    assert [item["requested"] for item in data["results"]] == [
        "typer",
        "definitely-not-installed-pkgwhy-precheck-req-1==1.0.0",
    ]
    assert data["decision"] == "block"
    assert data["exit_code"] == 2
    assert any("recursive include is not evaluated" in warning for warning in data["warnings"])


def test_precheck_requirements_normalizes_hash_locked_lines_and_skips_direct_references(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        """
demo-precheck-hash==1.0.0 \\
    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
direct-demo @ https://example.invalid/direct-demo.whl
""",
        encoding="utf-8",
    )

    result = build_requirements_precheck(requirements)

    assert result.package_count == 1
    assert result.results[0].requested == "demo-precheck-hash==1.0.0"
    assert any("URL, VCS, or file requirement" in warning for warning in result.warnings)


def test_precheck_cli_pyproject_json(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = ["typer"]

[project.optional-dependencies]
dev = ["definitely-not-installed-pkgwhy-precheck-pyproject-1==2.0.0"]
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["precheck", str(pyproject), "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    PrecheckBatchResult.model_validate(data)
    assert data["schema_version"] == "pkgwhy.precheck_batch.v1"
    assert data["command"] == "pkgwhy precheck"
    assert data["target"] == str(pyproject)
    assert data["exit_code_meaning"] == "blocked by policy or risk decision"
    assert data["recommended_next_action"]
    assert data["evidence_summary"]["evidence_count"] >= len(data["evidence"])
    assert data["source_freshness"] == "dependency_file_snapshot"
    assert data["target_type"] == "pyproject"
    assert data["package_count"] == 2
    assert data["exit_code"] == 2
    assert data["results"][0]["requested"] == "typer"
    assert data["results"][1]["requested"] == "definitely-not-installed-pkgwhy-precheck-pyproject-1==2.0.0"


def test_precheck_cli_accepts_renamed_pyproject_toml(tmp_path: Path) -> None:
    pyproject = tmp_path / "safe-pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = ["typer"]
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["precheck", str(pyproject), "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    PrecheckBatchResult.model_validate(data)
    assert data["schema_version"] == "pkgwhy.precheck_batch.v1"
    assert data["target_type"] == "pyproject"
    assert data["source"] == str(pyproject)
    assert data["target"] == str(pyproject)
    assert data["results"][0]["requested"] == "typer"


def test_precheck_cli_json_error_for_unrecognized_toml(tmp_path: Path) -> None:
    config = tmp_path / "settings.toml"
    config.write_text("[tool.demo]\nname = 'not a pyproject dependency file'\n", encoding="utf-8")

    result = runner.invoke(app, ["precheck", str(config), "--json"])

    assert result.exit_code == 3
    data = json.loads(result.output)
    assert data == {
        "schema_version": "pkgwhy.error.v1",
        "command": "pkgwhy precheck",
        "target": str(config),
        "target_type": "pyproject",
        "error_type": "PrecheckFileError",
        "message": f"TOML file is not a pyproject dependency file: {config}",
        "exit_code": 3,
        "exit_code_meaning": "tool, configuration, or user input error",
        "suggested_fix": "Pass a readable pyproject-style TOML file with a [project] table.",
    }


def test_precheck_cli_json_error_when_target_missing() -> None:
    result = runner.invoke(app, ["precheck", "--json"])

    assert result.exit_code == 3
    data = json.loads(result.output)
    assert data == {
        "schema_version": "pkgwhy.error.v1",
        "command": "pkgwhy precheck",
        "target": None,
        "target_type": None,
        "error_type": "PrecheckTargetError",
        "message": "precheck requires a package target, pyproject.toml, or -r/--requirement file",
        "exit_code": 3,
        "exit_code_meaning": "tool, configuration, or user input error",
        "suggested_fix": "Pass a package requirement, -r/--requirement FILE, or a pyproject-style TOML file.",
    }


def test_precheck_download_artifact_static_inspection_with_mocked_pypi(monkeypatch, tmp_path: Path) -> None:
    artifact = tmp_path / "demo_precheck-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("demo_precheck/__init__.py", "import subprocess\n")
    artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()

    payload = {
        "info": {
            "name": "demo-precheck",
            "version": "1.0.0",
            "summary": "Demo package",
            "license": "MIT",
        },
        "releases": {
            "1.0.0": [
                {
                    "filename": artifact.name,
                    "packagetype": "bdist_wheel",
                    "url": "https://user:token@example.invalid/private/demo_precheck-1.0.0-py3-none-any.whl?token=secret",
                    "digests": {"sha256": artifact_sha256},
                },
                {
                    "filename": "demo_precheck-1.0.0.tar.gz",
                    "packagetype": "sdist",
                    "url": "https://example.invalid/demo_precheck-1.0.0.tar.gz",
                    "digests": {"sha256": "unused"},
                }
            ]
        },
    }
    monkeypatch.setattr("pkgwhy.precheck.fetch_pypi_project", lambda package: payload)
    monkeypatch.setattr("pkgwhy.precheck._download_url", lambda url: artifact.read_bytes())

    result = build_package_precheck("demo-precheck==1.0.0", download_artifacts=True)

    assert result.network_requested is True
    assert result.artifacts_downloaded is True
    assert result.artifact_summary.status == "partial"
    assert result.artifact_summary.filename == artifact.name
    assert result.artifact_summary.url == "https://example.invalid/demo_precheck-1.0.0-py3-none-any.whl"
    assert result.artifact_summary.sha256_status == "verified"
    assert result.artifact_summary.extracted_file_count == 1
    assert result.exit_code == 4
    assert result.static_summary.status == "downloaded_artifact_static_analysis"
    assert result.package_judgement.source_availability == "artifact_source_present"
    assert "Subprocess or shell execution signals" in result.package_judgement.detected_capabilities
    assert any("Did not install, import, or execute" in item for item in result.evidence)
    assert any("additional artifact(s) were not inspected" in warning for warning in result.warnings)


def test_precheck_download_artifact_unavailable_maps_to_infrastructure_exit(monkeypatch) -> None:
    payload = {
        "info": {
            "name": "demo-precheck",
            "version": "1.0.0",
            "summary": "Demo package",
            "license": "MIT",
        },
        "releases": {"1.0.0": []},
    }
    monkeypatch.setattr("pkgwhy.precheck.fetch_pypi_project", lambda package: payload)

    result = build_package_precheck("demo-precheck==1.0.0", download_artifacts=True)

    assert result.artifact_summary.status == "unavailable"
    assert result.exit_code == 4


def test_precheck_download_artifact_rejects_unsafe_metadata_filename(monkeypatch) -> None:
    payload = {
        "info": {
            "name": "demo-precheck",
            "version": "1.0.0",
            "summary": "Demo package",
            "license": "MIT",
        },
        "releases": {
            "1.0.0": [
                {
                    "filename": "../demo_precheck-1.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://example.invalid/demo_precheck-1.0.0-py3-none-any.whl",
                    "digests": {"sha256": "unused"},
                }
            ]
        },
    }
    monkeypatch.setattr("pkgwhy.precheck.fetch_pypi_project", lambda package: payload)

    result = build_package_precheck("demo-precheck==1.0.0", download_artifacts=True)

    assert result.artifact_summary.status == "failed"
    assert result.artifacts_downloaded is False
    assert result.exit_code == 4
    assert any("unsafe artifact filename" in warning for warning in result.warnings)


def test_precheck_keep_artifacts_filesystem_error_returns_failed_summary(monkeypatch, tmp_path: Path) -> None:
    artifact_dir = tmp_path / "not-a-directory"
    artifact_dir.write_text("not a directory\n", encoding="utf-8")
    payload = {
        "info": {
            "name": "demo-precheck",
            "version": "1.0.0",
            "summary": "Demo package",
            "license": "MIT",
        },
        "releases": {
            "1.0.0": [
                {
                    "filename": "demo_precheck-1.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://example.invalid/demo_precheck-1.0.0-py3-none-any.whl",
                    "digests": {"sha256": "unused"},
                }
            ]
        },
    }
    monkeypatch.setattr("pkgwhy.precheck.fetch_pypi_project", lambda package: payload)

    result = build_package_precheck(
        "demo-precheck==1.0.0",
        download_artifacts=True,
        keep_artifacts=True,
        artifact_dir=artifact_dir,
    )

    assert result.artifact_summary.status == "failed"
    assert result.exit_code == 4
    assert any("Artifact download/static inspection failed" in warning for warning in result.warnings)


def test_precheck_tar_extraction_uses_static_file_copy(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    package_file = source / "demo_pkg.py"
    package_file.write_text("VALUE = 1\n", encoding="utf-8")
    archive_path = tmp_path / "demo.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(package_file, arcname="demo_pkg.py")

    extract_root = tmp_path / "extracted"
    extract_root.mkdir()
    extracted = _extract_tar(archive_path, extract_root)

    assert extracted == [extract_root / "demo_pkg.py"]
    assert (extract_root / "demo_pkg.py").read_text(encoding="utf-8") == "VALUE = 1\n"


def test_precheck_cli_enforce_exit_code_returns_gate_code() -> None:
    package_name = "definitely-not-installed-pkgwhy-precheck-enforce-1"
    result = runner.invoke(app, ["precheck", package_name, "--json", "--enforce-exit-code"])

    assert result.exit_code == 2
    data = json.loads(result.output)
    assert data["exit_code"] == 2

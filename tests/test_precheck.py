import json
from pathlib import Path

from typer.testing import CliRunner

from pkgwhy.cli import app
from pkgwhy.core.models import PrecheckBatchResult, PreInstallPackagePrecheckResult
from pkgwhy.metadata.installed import get_installed_package
from pkgwhy.precheck import build_package_precheck, parse_precheck_target

runner = CliRunner()


def test_parse_precheck_target_preserves_exact_version() -> None:
    parsed = parse_precheck_target("Typer==0.12.5")

    assert parsed.package == "Typer"
    assert parsed.normalized_package == "typer"
    assert parsed.specifier == "==0.12.5"
    assert parsed.exact_version == "0.12.5"


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
    assert result.vulnerability_summary.status == "not_requested"
    assert any("Did not install, import, or execute" in item for item in result.evidence)
    assert get_installed_package(package_name) is None


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


def test_precheck_cli_json_for_installed_package() -> None:
    assert get_installed_package("typer") is not None

    result = runner.invoke(app, ["precheck", "typer", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    PreInstallPackagePrecheckResult.model_validate(data)
    assert data["schema_version"] == "pkgwhy.precheck.v1"
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
    assert data["target_type"] == "requirements"
    assert data["package_count"] == 2
    assert [item["requested"] for item in data["results"]] == [
        "typer",
        "definitely-not-installed-pkgwhy-precheck-req-1==1.0.0",
    ]
    assert data["decision"] == "block"


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
    assert data["target_type"] == "pyproject"
    assert data["package_count"] == 2
    assert data["results"][0]["requested"] == "typer"
    assert data["results"][1]["requested"] == "definitely-not-installed-pkgwhy-precheck-pyproject-1==2.0.0"

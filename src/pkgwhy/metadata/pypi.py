from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from urllib import error, request
from urllib.parse import quote

from packaging.version import InvalidVersion, Version

from pkgwhy.core.models import Confidence, PackageProvenance
from pkgwhy.metadata.installed import normalize_package_name

PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"


class PyPIMetadataError(RuntimeError):
    """Raised when optional PyPI metadata lookup fails."""


def fetch_pypi_project(package_name: str, *, timeout_seconds: float = 10.0) -> dict[str, Any]:
    """Fetch PyPI JSON explicitly; callers decide when network access is allowed."""
    url = PYPI_JSON_URL.format(package=quote(package_name, safe=""))
    req = request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, error.HTTPError, json.JSONDecodeError) as exc:
        raise PyPIMetadataError(f"PyPI metadata lookup failed for {package_name}: {exc}") from exc


def provenance_from_pypi_payload(
    package_name: str,
    payload: dict[str, Any],
    *,
    audited_version: str | None = None,
) -> PackageProvenance:
    """Build a conservative provenance summary from a PyPI JSON payload."""
    info = payload.get("info")
    info = info if isinstance(info, dict) else {}
    reported_version = audited_version or _string_or_none(info.get("version"))
    project_urls = info.get("project_urls")
    project_urls = project_urls if isinstance(project_urls, dict) else {}
    normalized_urls = {
        str(key): value.strip()
        for key, value in project_urls.items()
        if isinstance(value, str) and value.strip()
    }
    repository_url = _find_url(normalized_urls, ("source", "repository", "github", "code"))
    documentation_url = _find_url(normalized_urls, ("doc", "documentation"))
    homepage_url = _string_or_none(info.get("home_page")) or _find_url(normalized_urls, ("homepage", "home-page"))
    releases = payload.get("releases")
    latest_release_date = _latest_release_date(releases)
    audited_release_date = _release_date(releases, reported_version)
    source_distribution_status = _source_distribution_status(releases, reported_version)
    evidence = ["Read project metadata from PyPI JSON payload."]
    warnings = [
        "Trusted Publishing status is not inferred from PyPI project JSON.",
        "Attestation verification is not implemented.",
        "Source distribution versus wheel comparison is not implemented.",
    ]

    if repository_url:
        evidence.append(f"Repository URL declared in PyPI metadata: {repository_url}")
    else:
        warnings.append("PyPI metadata does not declare a repository URL.")

    if audited_version is not None and reported_version:
        if audited_release_date:
            evidence.append(f"Observed PyPI upload time for audited version {reported_version}: {audited_release_date}")
            release_activity_status = f"audited_release_upload:{audited_release_date}"
        else:
            release_activity_status = "unknown"
            warnings.append(f"PyPI metadata did not include release files for audited version {reported_version}.")
            if latest_release_date:
                evidence.append(f"Latest observed PyPI release upload time: {latest_release_date}")
    elif latest_release_date:
        evidence.append(f"Latest observed PyPI release upload time: {latest_release_date}")
        release_activity_status = f"latest_release_upload:{latest_release_date}"
    else:
        release_activity_status = "unknown"
        warnings.append("Could not determine latest release upload time from PyPI metadata.")

    if source_distribution_status == "present":
        evidence.append("PyPI metadata lists at least one source distribution for the inspected release.")
    elif source_distribution_status == "not_found":
        warnings.append("PyPI metadata did not list a source distribution for the inspected release.")
    else:
        warnings.append("Could not determine source distribution status from PyPI metadata.")

    return PackageProvenance(
        package=normalize_package_name(package_name),
        version=reported_version,
        repository_url=repository_url,
        documentation_url=documentation_url,
        homepage_url=homepage_url,
        project_urls=normalized_urls,
        metadata_source="pypi_json",
        source_distribution_status=source_distribution_status,
        trusted_publishing_status="unknown",
        attestation_status="not_implemented",
        release_activity_status=release_activity_status,
        confidence=Confidence.MEDIUM if repository_url or latest_release_date else Confidence.LOW,
        warnings=warnings,
        evidence=evidence,
    )


def _find_url(values: dict[str, str], tokens: tuple[str, ...]) -> str | None:
    for key, value in values.items():
        lower = key.lower()
        if any(token in lower for token in tokens):
            return value
    return None


def _latest_release_date(releases: Any) -> str | None:
    if not isinstance(releases, dict):
        return None
    latest: datetime | None = None
    for files in releases.values():
        if not isinstance(files, list):
            continue
        for file_info in files:
            if not isinstance(file_info, dict):
                continue
            uploaded_at = _string_or_none(file_info.get("upload_time_iso_8601")) or _string_or_none(file_info.get("upload_time"))
            if uploaded_at is None:
                continue
            parsed = _parse_datetime(uploaded_at)
            if parsed is not None and (latest is None or parsed > latest):
                latest = parsed
    return latest.date().isoformat() if latest else None


def _release_date(releases: Any, version: str | None) -> str | None:
    files = _release_files(releases, version)
    if files is None:
        return None
    latest: datetime | None = None
    for file_info in files:
        if not isinstance(file_info, dict):
            continue
        uploaded_at = _string_or_none(file_info.get("upload_time_iso_8601")) or _string_or_none(file_info.get("upload_time"))
        if uploaded_at is None:
            continue
        parsed = _parse_datetime(uploaded_at)
        if parsed is not None and (latest is None or parsed > latest):
            latest = parsed
    return latest.date().isoformat() if latest else None


def _source_distribution_status(releases: Any, version: str | None) -> str:
    files = _release_files(releases, version)
    if files is None:
        return "unknown"
    for file_info in files:
        if not isinstance(file_info, dict):
            continue
        package_type = _string_or_none(file_info.get("packagetype"))
        filename = _string_or_none(file_info.get("filename"))
        if package_type == "sdist" or (filename is not None and filename.endswith((".tar.gz", ".zip"))):
            return "present"
    return "not_found"


def _release_files(releases: Any, version: str | None) -> list[Any] | None:
    if not isinstance(releases, dict) or version is None:
        return None
    files = releases.get(version)
    if isinstance(files, list):
        return files
    try:
        target = Version(version)
    except InvalidVersion:
        return None
    for release_version, release_files in releases.items():
        if not isinstance(release_version, str) or not isinstance(release_files, list):
            continue
        try:
            if Version(release_version) == target:
                return release_files
        except InvalidVersion:
            continue
    return None


def _parse_datetime(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _string_or_none(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped if stripped else None

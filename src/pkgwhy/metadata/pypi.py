from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from urllib import error, request

from pkgwhy.core.models import Confidence, PackageProvenance
from pkgwhy.metadata.installed import normalize_package_name

PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"


class PyPIMetadataError(RuntimeError):
    """Raised when optional PyPI metadata lookup fails."""


def fetch_pypi_project(package_name: str, *, timeout_seconds: float = 10.0) -> dict[str, Any]:
    """Fetch PyPI JSON explicitly; callers decide when network access is allowed."""
    url = PYPI_JSON_URL.format(package=package_name)
    req = request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, error.HTTPError, json.JSONDecodeError) as exc:
        raise PyPIMetadataError(f"PyPI metadata lookup failed for {package_name}: {exc}") from exc


def provenance_from_pypi_payload(package_name: str, payload: dict[str, Any]) -> PackageProvenance:
    """Build a conservative provenance summary from a PyPI JSON payload."""
    info = payload.get("info")
    info = info if isinstance(info, dict) else {}
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
    latest_release_date = _latest_release_date(payload.get("releases"))
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

    if latest_release_date:
        evidence.append(f"Latest observed PyPI release upload time: {latest_release_date}")
        release_activity_status = f"latest_release_upload:{latest_release_date}"
    else:
        release_activity_status = "unknown"
        warnings.append("Could not determine latest release upload time from PyPI metadata.")

    return PackageProvenance(
        package=normalize_package_name(package_name),
        version=_string_or_none(info.get("version")),
        repository_url=repository_url,
        documentation_url=documentation_url,
        homepage_url=homepage_url,
        project_urls=normalized_urls,
        metadata_source="pypi_json",
        source_distribution_status="unknown",
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


def _parse_datetime(value: str) -> datetime | None:
    normalized = value.removesuffix("Z") + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _string_or_none(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped if stripped else None

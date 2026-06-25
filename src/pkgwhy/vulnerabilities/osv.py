from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib import error, request

from pkgwhy.core.models import VulnerabilityRange, VulnerabilityRecord
from pkgwhy.metadata.installed import normalize_package_name

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_SOURCE = "OSV.dev"


class OSVClientError(RuntimeError):
    """Raised when the optional OSV client cannot retrieve advisory data."""


def load_osv_records(path: Path, package_name: str | None = None) -> list[VulnerabilityRecord]:
    """Load OSV-like JSON from a local file without network access."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read vulnerability data from {path}: {exc}") from exc
    return parse_osv_payload(payload, package_name=package_name)


def parse_osv_payload(payload: dict[str, Any] | list[Any], package_name: str | None = None) -> list[VulnerabilityRecord]:
    """Parse a minimal OSV response or vulnerability list into internal records."""
    if isinstance(payload, dict):
        vulnerabilities = payload.get("vulns", [])
    else:
        vulnerabilities = payload

    records: list[VulnerabilityRecord] = []
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        records.extend(_records_from_vulnerability(item, package_name=package_name))
    return records


def query_osv(package_name: str, version: str | None, *, timeout_seconds: float = 10.0) -> list[VulnerabilityRecord]:
    """Query OSV.dev explicitly; callers decide when network access is allowed."""
    query: dict[str, Any] = {"package": {"name": package_name, "ecosystem": "PyPI"}}
    if version is not None:
        query["version"] = version
    data = json.dumps(query).encode("utf-8")
    req = request.Request(
        OSV_QUERY_URL,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, error.HTTPError, json.JSONDecodeError) as exc:
        raise OSVClientError(f"OSV.dev query failed for {package_name}: {exc}") from exc
    return parse_osv_payload(payload, package_name=package_name)


def _records_from_vulnerability(item: dict[str, Any], package_name: str | None) -> list[VulnerabilityRecord]:
    vulnerability_id = item.get("id")
    if not isinstance(vulnerability_id, str) or not vulnerability_id:
        return []

    affected_entries = item.get("affected")
    if not isinstance(affected_entries, list):
        affected_entries = []

    records: list[VulnerabilityRecord] = []
    for affected in affected_entries:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        package_info = package if isinstance(package, dict) else {}
        affected_name = _string_or_none(package_info.get("name")) or package_name
        if not affected_name:
            continue
        ecosystem = _string_or_none(package_info.get("ecosystem"))
        if ecosystem and ecosystem.lower() not in {"pypi", "python"}:
            continue
        records.append(
            VulnerabilityRecord(
                id=vulnerability_id,
                aliases=_string_list(item.get("aliases")),
                package_name=normalize_package_name(affected_name),
                ecosystem=ecosystem,
                summary=_string_or_none(item.get("summary")),
                details=_string_or_none(item.get("details")),
                severity=_parse_severity(item.get("severity")),
                affected_ranges=_parse_ranges(affected.get("ranges")),
                affected_versions=_string_list(affected.get("versions")),
                fixed_versions=_fixed_versions_from_ranges(affected.get("ranges")),
                references=_parse_references(item.get("references")),
                source=OSV_SOURCE,
                source_url=f"https://osv.dev/vulnerability/{vulnerability_id}",
            )
        )
    return records


def _parse_ranges(value: Any) -> list[VulnerabilityRange]:
    if not isinstance(value, list):
        return []
    ranges: list[VulnerabilityRange] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        events = item.get("events")
        if not isinstance(events, list):
            continue
        introduced: str | None = None
        for event in events:
            if not isinstance(event, dict):
                continue
            if "introduced" in event:
                introduced = _string_or_none(event.get("introduced"))
                continue
            if "fixed" in event:
                ranges.append(
                    VulnerabilityRange(
                        introduced=introduced,
                        fixed=_string_or_none(event.get("fixed")),
                        range_type=_string_or_none(item.get("type")),
                    )
                )
                introduced = None
                continue
            if "last_affected" in event:
                ranges.append(
                    VulnerabilityRange(
                        introduced=introduced,
                        last_affected=_string_or_none(event.get("last_affected")),
                        range_type=_string_or_none(item.get("type")),
                    )
                )
                introduced = None
        if introduced is not None:
            ranges.append(VulnerabilityRange(introduced=introduced, range_type=_string_or_none(item.get("type"))))
    return ranges


def _fixed_versions_from_ranges(value: Any) -> list[str]:
    fixed: list[str] = []
    if not isinstance(value, list):
        return fixed
    for item in value:
        if not isinstance(item, dict):
            continue
        events = item.get("events")
        if not isinstance(events, list):
            continue
        for event in events:
            if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                fixed.append(event["fixed"])
    return sorted(set(fixed))


def _parse_references(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    refs: list[str] = []
    for item in value:
        if isinstance(item, dict) and isinstance(item.get("url"), str):
            refs.append(item["url"])
    return refs


def _parse_severity(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    severities: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        if isinstance(score, str):
            severities.append(score)
    return severities


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None

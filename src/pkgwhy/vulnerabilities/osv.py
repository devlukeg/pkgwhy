from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
from urllib import error, request

from pkgwhy.core.models import VulnerabilityRange, VulnerabilityRecord
from pkgwhy.metadata.installed import normalize_package_name

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_SOURCE = "OSV.dev"
OSV_CACHE_ENV = "PKGWHY_CACHE_HOME"


@dataclass(frozen=True)
class OSVLookupResult:
    """Cache-aware OSV lookup result with explicit freshness status."""

    records: list[VulnerabilityRecord]
    cache_status: str
    cache_path: Path | None = None
    warnings: tuple[str, ...] = ()


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
        if isinstance(payload.get("vulns"), list):
            vulnerabilities = payload["vulns"]
        elif isinstance(payload.get("id"), str):
            vulnerabilities = [payload]
        else:
            vulnerabilities = []
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
    payload = _fetch_osv_payload(package_name, version, timeout_seconds=timeout_seconds)
    return parse_osv_payload(payload, package_name=package_name)


def query_osv_cached(
    package_name: str,
    version: str | None,
    *,
    timeout_seconds: float = 10.0,
    cache_dir: Path | None = None,
) -> OSVLookupResult:
    """Query OSV.dev with a stale-cache fallback for explicitly online callers."""
    resolved_cache_dir = cache_dir or default_osv_cache_dir()
    cache_path = _cache_path(resolved_cache_dir, package_name, version)
    try:
        payload = _fetch_osv_payload(package_name, version, timeout_seconds=timeout_seconds)
    except OSVClientError as exc:
        cached = _read_cached_payload(cache_path)
        warning = (
            f"OSV.dev lookup unavailable for {package_name} {version or 'unknown-version'}: {exc}. "
            "Missing vulnerability matches are not proof of safety."
        )
        if cached is None:
            return OSVLookupResult(records=[], cache_status="unavailable", cache_path=cache_path, warnings=(warning,))
        records = parse_osv_payload(cached, package_name=package_name)
        return OSVLookupResult(
            records=records,
            cache_status="stale_cache",
            cache_path=cache_path,
            warnings=(
                warning,
                "Using cached OSV.dev response. Cached advisory data may be stale.",
            ),
        )

    warnings = _write_cached_payload(cache_path, package_name, version, payload)
    return OSVLookupResult(
        records=parse_osv_payload(payload, package_name=package_name),
        cache_status="fresh",
        cache_path=cache_path,
        warnings=tuple(warnings),
    )


def default_osv_cache_dir() -> Path:
    """Return the default OSV cache directory without creating it."""
    configured = os.environ.get(OSV_CACHE_ENV)
    root = Path(configured).expanduser() if configured else Path.home() / ".cache" / "pkgwhy"
    return root / "vulnerabilities" / "osv"


def _fetch_osv_payload(package_name: str, version: str | None, *, timeout_seconds: float) -> dict[str, Any]:
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
            return json.loads(response.read().decode("utf-8"))
    except (OSError, error.HTTPError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OSVClientError(f"OSV.dev query failed for {package_name}: {exc}") from exc


def _cache_path(cache_dir: Path, package_name: str, version: str | None) -> Path:
    normalized = normalize_package_name(package_name)
    version_part = version or "no-version"
    digest = hashlib.sha256(f"{normalized}\0{version_part}".encode("utf-8")).hexdigest()[:16]
    return cache_dir / f"{normalized}-{digest}.json"


def _write_cached_payload(cache_path: Path, package_name: str, version: str | None, payload: dict[str, Any]) -> list[str]:
    document = {
        "schema_version": "pkgwhy.osv_cache.v1",
        "source": OSV_SOURCE,
        "package": package_name,
        "version": version,
        "fetched_at": datetime.now(UTC).isoformat(),
        "payload": payload,
    }
    tmp_path: Path | None = None
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(document, indent=2, sort_keys=True)
        with NamedTemporaryFile("w", dir=cache_path.parent, encoding="utf-8", delete=False) as tmp_file:
            tmp_file.write(serialized)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            tmp_path = Path(tmp_file.name)
        os.replace(tmp_path, cache_path)
    except OSError:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        return ["Could not write OSV.dev cache."]
    return []


def _read_cached_payload(cache_path: Path) -> dict[str, Any] | None:
    try:
        document = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    payload = document.get("payload")
    return payload if isinstance(payload, dict) else None


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
            if "limit" in event:
                ranges.append(
                    VulnerabilityRange(
                        introduced=introduced,
                        limit=_string_or_none(event.get("limit")),
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

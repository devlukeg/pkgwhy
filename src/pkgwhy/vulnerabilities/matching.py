from __future__ import annotations

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pkgwhy.core.models import Confidence, VulnerabilityMatch, VulnerabilityRecord, VulnerabilityRange


def match_vulnerabilities(package: str, version: str | None, records: list[VulnerabilityRecord]) -> list[VulnerabilityMatch]:
    """Return conservative matches for one package/version against advisory records."""
    if version is None:
        return []
    matches: dict[str, VulnerabilityMatch] = {}
    for record in records:
        match = match_vulnerability(package, version, record)
        if match is not None:
            matches.setdefault(match.vulnerability_id, match)
    return sorted(matches.values(), key=lambda item: item.vulnerability_id)


def match_vulnerability(package: str, version: str, record: VulnerabilityRecord) -> VulnerabilityMatch | None:
    if canonicalize_name(record.package_name) != canonicalize_name(package):
        return None

    evidence: list[str] = []
    if _version_in_list(version, record.affected_versions):
        evidence.append(f"Version {version} is explicitly listed as affected by {record.id}.")
        return _build_match(record, package, version, evidence)

    for affected_range in record.affected_ranges:
        if _version_in_range(version, affected_range):
            evidence.append(
                f"Version {version} matched affected range "
                f"introduced={affected_range.introduced or 'unknown'} "
                f"fixed={affected_range.fixed or 'none'} "
                f"last_affected={affected_range.last_affected or 'none'} "
                f"limit={affected_range.limit or 'none'}."
            )
            return _build_match(record, package, version, evidence)

    return None


def _version_in_range(version: str, affected_range: VulnerabilityRange) -> bool:
    if not any((affected_range.introduced, affected_range.fixed, affected_range.last_affected)):
        return False
    range_type = affected_range.range_type.upper() if affected_range.range_type is not None else None
    if range_type not in {None, "ECOSYSTEM", "PYPI"}:
        return False

    try:
        parsed_version = Version(version)
    except InvalidVersion:
        return False

    if affected_range.introduced not in {None, "", "0"}:
        try:
            if parsed_version < Version(affected_range.introduced):
                return False
        except InvalidVersion:
            return False

    if affected_range.fixed:
        try:
            if parsed_version >= Version(affected_range.fixed):
                return False
        except InvalidVersion:
            return False

    if affected_range.last_affected:
        try:
            if parsed_version > Version(affected_range.last_affected):
                return False
        except InvalidVersion:
            return False

    if affected_range.limit:
        try:
            if parsed_version >= Version(affected_range.limit):
                return False
        except InvalidVersion:
            return False

    return True


def _version_in_list(version: str, candidates: list[str]) -> bool:
    if version in candidates:
        return True
    try:
        parsed_version = Version(version)
    except InvalidVersion:
        return False
    for candidate in candidates:
        try:
            if parsed_version == Version(candidate):
                return True
        except InvalidVersion:
            continue
    return False


def _build_match(record: VulnerabilityRecord, package: str, version: str, evidence: list[str]) -> VulnerabilityMatch:
    evidence.append(f"Advisory source: {record.source}.")
    if record.source_url:
        evidence.append(f"Advisory URL: {record.source_url}.")
    return VulnerabilityMatch(
        vulnerability_id=record.id,
        package=package,
        version=version,
        aliases=record.aliases,
        summary=record.summary,
        severity=record.severity,
        fixed_versions=record.fixed_versions,
        references=record.references,
        source=record.source,
        source_url=record.source_url,
        confidence=Confidence.MEDIUM,
        evidence=evidence,
    )

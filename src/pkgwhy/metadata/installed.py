from __future__ import annotations

from importlib import metadata
from importlib.metadata import Distribution

from packaging.utils import canonicalize_name

from pkgwhy.core.models import PackageIdentity, PackageMetadata, ProjectUrls


def normalize_package_name(name: str) -> str:
    return canonicalize_name(name)


def list_installed_packages() -> list[PackageMetadata]:
    packages = [metadata_from_distribution(dist) for dist in metadata.distributions()]
    return sorted(packages, key=lambda package: package.identity.normalized_name)


def get_installed_package(name: str) -> PackageMetadata | None:
    dist = find_distribution(name)
    return metadata_from_distribution(dist) if dist is not None else None


def get_distribution(name: str) -> Distribution | None:
    """Return the installed distribution for callers that need file-level inspection."""
    return find_distribution(name)


def find_distribution(name: str) -> Distribution | None:
    wanted = normalize_package_name(name)
    for dist in metadata.distributions():
        dist_name = dist.metadata.get("Name")
        if dist_name and normalize_package_name(dist_name) == wanted:
            return dist
    return None


def metadata_from_distribution(dist: Distribution) -> PackageMetadata:
    meta = dist.metadata
    name = meta.get("Name") or "unknown"
    project_urls = parse_project_urls(meta.get_all("Project-URL") or [])
    entry_points = [
        f"{entry_point.group}:{entry_point.name}={entry_point.value}"
        for entry_point in dist.entry_points
    ]
    return PackageMetadata(
        identity=PackageIdentity(
            name=name,
            normalized_name=normalize_package_name(name),
            version=meta.get("Version"),
        ),
        summary=meta.get("Summary"),
        author=meta.get("Author"),
        maintainer=meta.get("Maintainer"),
        license=meta.get("License"),
        requires=list(meta.get_all("Requires-Dist") or []),
        project_urls=project_urls,
        entry_points=entry_points,
        metadata_available=True,
    )


def parse_project_urls(values: list[str]) -> ProjectUrls:
    raw: dict[str, str] = {}
    homepage: str | None = None
    repository: str | None = None
    documentation: str | None = None
    for value in values:
        if "," not in value:
            continue
        label, url = value.split(",", 1)
        label = label.strip()
        url = url.strip()
        raw[label] = url
        key = label.lower()
        if homepage is None and key in {"homepage", "home-page"}:
            homepage = url
        if repository is None and any(token in key for token in ("source", "repository", "github", "code")):
            repository = url
        if documentation is None and any(token in key for token in ("doc", "documentation")):
            documentation = url
    return ProjectUrls(homepage=homepage, repository=repository, documentation=documentation, raw=raw)

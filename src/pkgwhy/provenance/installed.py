from __future__ import annotations

from pkgwhy.core.models import Confidence, PackageMetadata, PackageProvenance


def assess_installed_provenance(metadata: PackageMetadata) -> PackageProvenance:
    """Summarize source-trust signals available from installed metadata only."""
    urls = metadata.project_urls
    raw_urls = dict(urls.raw)
    evidence = ["Read project URLs from installed distribution metadata."]
    warnings = [
        "Trusted Publishing status is unknown from installed metadata.",
        "Attestation verification is not implemented.",
        "Source distribution versus wheel comparison is not implemented.",
        "Release activity requires optional online metadata and is not available from installed metadata alone.",
    ]
    confidence = Confidence.LOW

    if urls.repository:
        evidence.append(f"Repository URL declared in installed metadata: {urls.repository}")
        confidence = Confidence.MEDIUM
    else:
        warnings.append("No repository URL was found in installed metadata.")

    if urls.documentation:
        evidence.append(f"Documentation URL declared in installed metadata: {urls.documentation}")

    if urls.homepage:
        evidence.append(f"Homepage URL declared in installed metadata: {urls.homepage}")

    if not raw_urls:
        warnings.append("Installed metadata does not declare project URLs.")

    return PackageProvenance(
        package=metadata.identity.normalized_name,
        version=metadata.identity.version,
        repository_url=urls.repository,
        documentation_url=urls.documentation,
        homepage_url=urls.homepage,
        project_urls=raw_urls,
        confidence=confidence,
        warnings=warnings,
        evidence=evidence,
    )

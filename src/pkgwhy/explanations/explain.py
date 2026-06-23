from __future__ import annotations

from packaging.utils import canonicalize_name

from pkgwhy.core.models import Confidence, PackageExplanation, PackageMetadata
from pkgwhy.explanations.local_db import LOCAL_EXPLANATIONS


def explain_package(metadata: PackageMetadata | None, requested_name: str, dependency_status: str) -> PackageExplanation:
    normalized = canonicalize_name(requested_name)
    base = LOCAL_EXPLANATIONS.get(normalized)
    if base is not None:
        explanation = base.model_copy(deep=True)
        explanation.version = metadata.identity.version if metadata else None
        explanation.dependency_status = dependency_status
        return explanation

    if metadata is None:
        return PackageExplanation(
            package=normalized,
            summary="No installed metadata was found for this package in the active Python environment.",
            dependency_status=dependency_status,
            confidence=Confidence.LOW,
            sources_used=["active environment metadata lookup"],
        )

    summary = metadata.summary or "Installed package metadata does not include a summary."
    return PackageExplanation(
        package=normalized,
        version=metadata.identity.version,
        summary=summary,
        why_it_might_be_installed=_why_from_metadata(metadata),
        dependency_status=dependency_status,
        confidence=Confidence.MEDIUM if metadata.summary else Confidence.LOW,
        sources_used=["installed distribution metadata"],
    )


def _why_from_metadata(metadata: PackageMetadata) -> list[str]:
    reasons: list[str] = []
    if metadata.entry_points:
        reasons.append("It declares CLI or plugin entry points.")
    if metadata.requires:
        reasons.append("It declares dependencies on other packages.")
    if metadata.summary:
        reasons.append("Its installed metadata summary describes its intended purpose.")
    return reasons or ["Installed metadata is available, but why it is installed is not yet known."]

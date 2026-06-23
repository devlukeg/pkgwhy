from __future__ import annotations

import re

from pkgwhy.core.models import TyposquatCandidate
from pkgwhy.metadata.installed import normalize_package_name
from pkgwhy.typosquat.popular_packages import KNOWN_LEGITIMATE_FAMILIES, POPULAR_PACKAGE_REFERENCES

HOMOGLYPH_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)


def detect_typosquat(package_name: str) -> TyposquatCandidate | None:
    """Return the strongest conservative typosquat signal for a package name."""

    normalized = normalize_package_name(package_name)
    if normalized in KNOWN_LEGITIMATE_FAMILIES:
        return None

    best: TyposquatCandidate | None = None
    for target, references in POPULAR_PACKAGE_REFERENCES.items():
        if normalized == normalize_package_name(target):
            continue
        if _is_known_family_package(normalized, target):
            continue
        for reference in references:
            candidate = _compare_to_reference(package_name, normalized, target, reference)
            if candidate is None:
                continue
            if best is None or candidate.similarity > best.similarity:
                best = candidate
    return best


def detect_typosquats(package_names: list[str]) -> list[TyposquatCandidate]:
    candidates = [detect_typosquat(name) for name in package_names]
    return sorted(
        [candidate for candidate in candidates if candidate is not None],
        key=lambda item: (-item.similarity, -len(item.signals), item.package),
    )


def _compare_to_reference(
    package_name: str,
    normalized: str,
    target: str,
    reference: str,
) -> TyposquatCandidate | None:
    reference_normalized = normalize_package_name(reference)
    candidate_compact = _compact(normalized)
    reference_compact = _compact(reference_normalized)
    candidate_homoglyph = _homoglyph_normalize(candidate_compact)
    reference_homoglyph = _homoglyph_normalize(reference_compact)

    signals: list[str] = []
    evidence: list[str] = []
    distance = _levenshtein(candidate_compact, reference_compact)
    max_length = max(len(candidate_compact), len(reference_compact), 1)
    similarity = 1 - (distance / max_length)

    if distance <= 2 and similarity >= 0.72:
        signals.append("edit_distance")
        evidence.append(f"Edit distance to popular package reference '{reference}' is {distance}.")
    if _is_adjacent_transposition(candidate_compact, reference_compact):
        signals.append("adjacent_transposition")
        evidence.append(f"Name appears to transpose adjacent characters from '{reference}'.")
        similarity = max(similarity, 0.92)
    if _is_single_missing_or_extra_character(candidate_compact, reference_compact):
        signals.append("missing_or_extra_character")
        evidence.append(f"Name differs from '{reference}' by one missing or extra character.")
        similarity = max(similarity, 0.88)
    if candidate_homoglyph == reference_homoglyph and candidate_compact != reference_compact:
        signals.append("homoglyph_or_lookalike")
        evidence.append(f"Name normalizes to the same lookalike form as '{reference}'.")
        similarity = max(similarity, 0.95)

    if len(signals) == 0:
        return None

    return TyposquatCandidate(
        package=package_name,
        normalized_package=normalized,
        possible_target=target,
        matched_reference=reference,
        similarity=round(similarity, 3),
        signals=sorted(set(signals)),
        is_possible_typosquat=True,
        recommendation="Possible typosquatting risk. Review package identity, source, maintainer, and purpose before use.",
        evidence=evidence,
    )


def _is_known_family_package(normalized: str, target: str) -> bool:
    target_normalized = normalize_package_name(target)
    return (
        normalized.startswith(f"{target_normalized}-")
        or normalized.endswith(f"-{target_normalized}")
        or normalized == f"types-{target_normalized}"
        or normalized == f"{target_normalized}-stubs"
    )


def _compact(value: str) -> str:
    return re.sub(r"[-_.]+", "", value.lower())


def _homoglyph_normalize(value: str) -> str:
    return value.translate(HOMOGLYPH_TRANSLATION)


def _is_adjacent_transposition(candidate: str, reference: str) -> bool:
    if len(candidate) != len(reference) or candidate == reference:
        return False
    differences = [index for index, (left, right) in enumerate(zip(candidate, reference, strict=True)) if left != right]
    if len(differences) != 2:
        return False
    first, second = differences
    return second == first + 1 and candidate[first] == reference[second] and candidate[second] == reference[first]


def _is_single_missing_or_extra_character(candidate: str, reference: str) -> bool:
    if abs(len(candidate) - len(reference)) != 1:
        return False
    shorter, longer = sorted((candidate, reference), key=len)
    index = 0
    skipped = False
    for char in longer:
        if index < len(shorter) and shorter[index] == char:
            index += 1
        elif skipped:
            return False
        else:
            skipped = True
    return True


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            substitution_cost = 0 if left_char == right_char else 1
            current.append(
                min(
                    previous[right_index] + 1,
                    current[right_index - 1] + 1,
                    previous[right_index - 1] + substitution_cost,
                )
            )
        previous = current
    return previous[-1]

"""PEP 440 version resolution for application profile references."""

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..models.application_profile import ApplicationProfile
from ..models.test_profile import ApplicationProfileReference


def resolve_application_profiles(
    references: list[ApplicationProfileReference],
    available_profiles: list[ApplicationProfile],
) -> dict[tuple[str, str], ApplicationProfile | None]:
    """Resolve application profile references to concrete profiles using PEP 440.

    For each reference, finds the highest-version ApplicationProfile whose name
    matches and whose version satisfies the PEP 440 constraint.

    Args:
        references: List of profile references with name and version constraint.
        available_profiles: All available application profiles to match against.

    Returns:
        Dict mapping (profile_name, version_constraint) to the resolved
        ApplicationProfile, or None if no match was found.
    """
    # Group available profiles by name for efficient lookup
    profiles_by_name: dict[str, list[ApplicationProfile]] = {}
    for ap in available_profiles:
        profiles_by_name.setdefault(ap.name, []).append(ap)

    result: dict[tuple[str, str], ApplicationProfile | None] = {}

    for ref in references:
        key = (ref.profile_name, ref.profile_version)
        candidates = profiles_by_name.get(ref.profile_name, [])

        if not candidates:
            result[key] = None
            continue

        result[key] = _resolve_best_match(ref.profile_version, candidates)

    return result


def _resolve_best_match(
    constraint_str: str,
    candidates: list[ApplicationProfile],
) -> ApplicationProfile | None:
    """Find the highest-version candidate satisfying a PEP 440 constraint.

    Falls back to exact string match if the constraint is not a valid
    PEP 440 specifier (e.g., a bare version like "1.0.0").
    """
    # Try parsing as a PEP 440 specifier set (e.g., "~=1.0.0", ">=1.0,<2.0")
    try:
        specifier = SpecifierSet(constraint_str)
    except InvalidSpecifier:
        # Not a valid specifier — try exact version match
        return _exact_match(constraint_str, candidates)

    # Filter candidates whose version satisfies the specifier
    matched: list[tuple[Version, ApplicationProfile]] = []
    for ap in candidates:
        try:
            v = Version(ap.version)
        except InvalidVersion:
            continue
        if v in specifier:
            matched.append((v, ap))

    if not matched:
        return None

    # Return the candidate with the highest version
    matched.sort(key=lambda pair: pair[0], reverse=True)
    return matched[0][1]


def _exact_match(
    version_str: str,
    candidates: list[ApplicationProfile],
) -> ApplicationProfile | None:
    """Fall back to exact string match on version."""
    for ap in candidates:
        if ap.version == version_str:
            return ap
    return None

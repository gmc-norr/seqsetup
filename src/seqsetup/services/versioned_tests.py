"""Test versions (spec 2026-10-07 group A4): the rule for a test profile's
Version, finding the test profile a sample's test and version name, and the
tests a pick-list offers."""

import re
from dataclasses import dataclass
from typing import Optional

from ..models.test_profile import TestProfile

# A test profile's Version: three whole numbers joined by dots, each 0 or
# without a leading zero and at most 9 digits, so it always turns into numbers.
PROFILE_VERSION_RE = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")
PROFILE_VERSION_RULE = (
    "must be three whole numbers joined by dots, each at most 9 digits, like 1.0.0"
)


def version_numbers(text: str) -> tuple[int, ...]:
    """The numbers of a version that follows its rule (a sample's or a
    profile's), so 1.10.0 sorts after 1.9.0."""
    return tuple(int(part) for part in text.split("."))


@dataclass(frozen=True)
class OfferedTest:
    """One test in a pick-list: its name, and the synced versions, oldest
    first. Stored versions that break the rule are not offered (§1)."""

    test_type: str
    test_name: str
    versions: tuple[str, ...]


def offered_tests(profiles) -> list[OfferedTest]:
    """Each stored test once, sorted by test, named by its newest version."""
    by_test: dict[str, list] = {}
    for profile in profiles:
        by_test.setdefault(profile.test_type, []).append(profile)
    offered = []
    for test in sorted(by_test):
        usable = sorted((p for p in by_test[test] if PROFILE_VERSION_RE.match(p.version)),
                        key=lambda p: version_numbers(p.version))
        newest = usable[-1] if usable else by_test[test][0]
        versions = tuple(dict.fromkeys(p.version for p in usable))
        offered.append(OfferedTest(test, newest.test_name, versions))
    return offered


@dataclass(frozen=True)
class ResolvedTest:
    """The test profile a sample's test and version name, or why there is
    none: ``error_type`` and ``detail`` are what the checks show (§3)."""

    profile: Optional[TestProfile]
    error_type: str = ""
    detail: str = ""


def resolve_test(test_profile_repo, test: str, asked: str) -> ResolvedTest:
    """The newest stored version of ``test`` whose numbers start with those
    of ``asked`` ("1" asks for the newest 1.x.x, "1.2" for 1.2.x, "1.2.3"
    for exactly it). Never "the first one the database returns" (review
    S-12). ``asked`` follows the sample's rule (models/sample.py)."""
    stored = test_profile_repo.list_by_test_type(test)
    if not stored:
        return ResolvedTest(None, "test_profile_not_found",
                            f"No test profile found for test type '{test}'")
    # The pattern before any number: a stored version from before this rule
    # is skipped, and never raises (spec §1).
    usable = sorted(((version_numbers(p.version), p) for p in stored
                     if PROFILE_VERSION_RE.match(p.version)), key=lambda pair: pair[0])
    wanted = version_numbers(asked)
    matches = [(numbers, p) for numbers, p in usable if numbers[:len(wanted)] == wanted]
    if not matches:
        synced = ", ".join(dict.fromkeys(p.version for _, p in usable)) or "none"
        return ResolvedTest(None, "test_version_not_found",
                            f"No synced {test} version matches {asked}. "
                            f"Synced {test} versions: {synced}.")
    newest = matches[-1][0]
    top = [p for numbers, p in matches if numbers == newest]
    if len(top) > 1:
        times = "twice" if len(top) == 2 else f"{len(top)} times"
        files = ", ".join(sorted(p.source_file for p in top))
        return ResolvedTest(None, "test_version_stored_twice",
                            f"{test} {top[0].version} is stored {times} ({files}). "
                            f"Sync the profiles again.")
    return ResolvedTest(top[0])

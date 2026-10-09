"""Test versions (spec 2026-10-07 group A4): the rule for a test profile's
Version, and the tests a pick-list offers."""

import re
from dataclasses import dataclass

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

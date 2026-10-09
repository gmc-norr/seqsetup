"""Finding a sample's test profile from its test and version (spec
2026-10-07 group A4, §1): the newest synced version that starts with the
sample's numbers, never "the first one the database returns"."""

import mongomock
import pytest

from seqsetup.services.versioned_tests import resolve_test


def _profile(version, test="WGS", source_file=None):
    # Imported here: a module-level TestProfile would be collected by pytest.
    from seqsetup.models.test_profile import TestProfile
    return TestProfile(test_type=test, test_name=test, version=version,
                       source_file=source_file or f"{test}_{version}.yaml")


class _Repo:
    """A test-profile store holding ``profiles``, in this order."""

    def __init__(self, *profiles):
        self.profiles = profiles

    def list_by_test_type(self, test):
        return [p for p in self.profiles if p.test_type == test]


STORED = _Repo(*(_profile(v) for v in ("1.2.0", "2.0.0", "1.10.0", "1.0.0", "1.2.5")),
               _profile("3.0.0", "RNA"))


class TestMatching:
    @pytest.mark.parametrize("asked,version", [
        ("1", "1.10.0"),      # 1.10.0 is newer than 1.2.5: compared as numbers
        ("1.2", "1.2.5"),
        ("1.2.0", "1.2.0"),
        ("1.10", "1.10.0"),
        ("2", "2.0.0"),
        ("2.0.0", "2.0.0"),
    ])
    def test_the_newest_match(self, asked, version):
        resolved = resolve_test(STORED, "WGS", asked)
        assert (resolved.profile.version, resolved.error_type, resolved.detail) == (version, "", "")

    @pytest.mark.parametrize("asked", ["1.9", "1.2.1", "3", "0"])
    def test_no_match(self, asked):
        resolved = resolve_test(STORED, "WGS", asked)
        assert resolved.profile is None
        assert resolved.error_type == "test_version_not_found"
        assert resolved.detail == (
            f"No synced WGS version matches {asked}. "
            "Synced WGS versions: 1.0.0, 1.2.0, 1.2.5, 1.10.0, 2.0.0.")

    def test_no_profile_of_that_test(self):
        resolved = resolve_test(STORED, "WES", "1")
        assert (resolved.profile, resolved.error_type, resolved.detail) == (
            None, "test_profile_not_found", "No test profile found for test type 'WES'")


class TestNumbersNotText:
    """A version is matched number by number, never as text: 1 is not the
    start of 10.0.0, nor 1.2 of 1.20.0 (spec §1)."""

    @pytest.mark.parametrize("stored,asked,version", [
        (("1.0.0", "10.0.0", "11.0.0"), "1", "1.0.0"),
        (("1.2.0", "1.20.0"), "1.2", "1.2.0"),
        (("2.1.0", "2.10.0"), "2.1", "2.1.0"),
        (("1.0.0", "10.0.0"), "10", "10.0.0"),
    ])
    def test_a_longer_number_does_not_match(self, stored, asked, version):
        resolved = resolve_test(_Repo(*(_profile(v) for v in stored)), "WGS", asked)
        assert resolved.profile.version == version


class TestStoredRecordsThatCannotBeUsed:
    def test_a_version_that_breaks_the_rule_is_skipped(self):
        # Only a sync from before group A4 can have stored them (spec §1).
        repo = _Repo(_profile("1.5"), _profile("9" * 4301 + ".0.0"), _profile("1.1.0"))
        resolved = resolve_test(repo, "WGS", "1")
        assert resolved.profile.version == "1.1.0"

    def test_only_unusable_versions(self):
        resolved = resolve_test(_Repo(_profile("1.5")), "WGS", "1")
        assert (resolved.error_type, resolved.detail) == (
            "test_version_not_found",
            "No synced WGS version matches 1. Synced WGS versions: none.")

    def test_the_newest_match_stored_twice(self):
        repo = _Repo(_profile("1.2.0", source_file="Wgs_b.yaml"),
                     _profile("1.2.0", source_file="Wgs_a.yaml"), _profile("1.1.0"))
        resolved = resolve_test(repo, "WGS", "1")
        assert (resolved.profile, resolved.error_type, resolved.detail) == (
            None, "test_version_stored_twice",
            "WGS 1.2.0 is stored twice (Wgs_a.yaml, Wgs_b.yaml). Sync the profiles again.")

    def test_three_times(self):
        repo = _Repo(*(_profile("1.2.0", source_file=f"{n}.yaml") for n in "cab"))
        assert resolve_test(repo, "WGS", "1").detail == (
            "WGS 1.2.0 is stored 3 times (a.yaml, b.yaml, c.yaml). Sync the profiles again.")

    def test_an_older_match_stored_twice_does_not_matter(self):
        repo = _Repo(_profile("1.2.0", source_file="a.yaml"),
                     _profile("1.2.0", source_file="b.yaml"), _profile("1.3.0"))
        assert resolve_test(repo, "WGS", "1").profile.version == "1.3.0"


def _mongo_repo():
    # Imported here: a module-level TestProfileRepository would be collected by pytest.
    from seqsetup.repositories.test_profile_repo import TestProfileRepository
    return TestProfileRepository(mongomock.MongoClient().db)


class TestStorageOrder:
    """The review's S-12: which WGS a sample got followed storage order
    (measured on e65c60d: 1.0.0 in one order, 2.0.0 in the other)."""

    @pytest.mark.parametrize("order", [("1.0.0", "2.0.0"), ("2.0.0", "1.0.0")])
    @pytest.mark.parametrize("asked,version", [("1", "1.0.0"), ("2", "2.0.0")])
    def test_the_same_answer_in_both_orders(self, order, asked, version):
        repo = _mongo_repo()
        for stored in order:
            repo.save(_profile(stored))
        assert resolve_test(repo, "WGS", asked).profile.version == version

    def test_the_repository_lists_every_version(self):
        repo = _mongo_repo()
        for stored in ("1.0.0", "2.0.0"):
            repo.save(_profile(stored))
        repo.save(_profile("1.0.0", "RNA"))
        assert sorted(p.version for p in repo.list_by_test_type("WGS")) == ["1.0.0", "2.0.0"]
        assert not hasattr(repo, "get_by_test_type")

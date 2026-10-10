"""The test pick-lists show each test once, with its synced versions
(spec 2026-10-07 group A4, §2)."""

from seqsetup.services.versioned_tests import offered_tests


def _profile(test, version, name=""):
    # Imported here: a module-level TestProfile would be collected by pytest.
    from seqsetup.models.test_profile import TestProfile
    return TestProfile(test_type=test, test_name=name or test, version=version)


class TestTheOfferedTests:
    def test_one_entry_per_test_sorted_by_test(self):
        choices = offered_tests([_profile("WGS", "1.0.0"), _profile("RNA", "2.0.0"),
                                _profile("WGS", "1.2.0")])
        assert [(c.test_type, c.versions) for c in choices] == [
            ("RNA", ("2.0.0",)), ("WGS", ("1.0.0", "1.2.0"))]

    def test_versions_are_sorted_as_numbers(self):
        choices = offered_tests([_profile("WGS", "1.10.0"), _profile("WGS", "1.9.0"),
                                _profile("WGS", "1.9.10")])
        assert choices[0].versions == ("1.9.0", "1.9.10", "1.10.0")

    def test_the_name_comes_from_the_newest_version(self):
        choices = offered_tests([_profile("WGS", "2.0.0", "Whole genome v2"),
                                _profile("WGS", "1.0.0", "Whole genome")])
        assert choices[0].test_name == "Whole genome v2"

    def test_a_stored_version_that_breaks_the_rule_is_not_offered(self):
        # Only a sync from before group A4 can have stored it (spec §1).
        choices = offered_tests([_profile("WGS", "1.0"), _profile("WGS", "1.2.0")])
        assert choices[0].versions == ("1.2.0",)

    def test_a_test_with_no_usable_version_is_still_listed(self):
        choices = offered_tests([_profile("WGS", "1.0", "Whole genome")])
        assert [(c.test_type, c.test_name, c.versions) for c in choices] == [
            ("WGS", "Whole genome", ())]

    def test_nothing_stored_gives_nothing(self):
        assert offered_tests([]) == []

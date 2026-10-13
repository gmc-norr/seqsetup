"""The repeated-test refusal names each file by its path in the repository.

A test and version may be in one file only, and the refusal names the files
that hold it. It named them by base name, so two files in different folders
of the test-profile tree read as the same file -- "WGS 1.2.0 is in Wgs.yaml
and Wgs.yaml" -- and an admin had nothing to go on to find the second one.
"""

import pytest

from seqsetup.services.github_sync import GitHubSyncService

from .test_group_a4 import FOLDER, REFUSED, TESTS_BEFORE, _sync_tests, _test_yaml


class TestTheRepeatedTestRefusalNamesPaths:
    def test_two_files_of_one_name_in_two_folders(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, message, logged = _sync_tests(ctx, monkeypatch, {
            "Wgs.yaml": _test_yaml("1.2.0"),
            "archive": {"Wgs.yaml": _test_yaml("1.2.0")},
        })

        assert ok is False
        where = (f"WGS 1.2.0 is in {FOLDER}/Wgs.yaml and {FOLDER}/archive/Wgs.yaml")
        assert REFUSED + where + ". " in message
        assert any(where in m for m in logged), logged

    def test_two_files_in_the_top_folder(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            "Wgs_a.yaml": _test_yaml("1.2.0"), "Wgs_b.yaml": _test_yaml("1.2.0")})

        assert ok is False
        assert (REFUSED + f"WGS 1.2.0 is in {FOLDER}/Wgs_a.yaml and "
                f"{FOLDER}/Wgs_b.yaml. ") in message

    def test_a_test_in_one_file_only_is_not_refused(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)

        assert ok, message

    def test_a_file_in_a_sub_folder_keeps_its_own_base_name_as_source(
            self, fresh_app, monkeypatch):
        """What is stored on the profile does not change: source_file is the
        file's own name, as every page and the validation report show it."""
        _app, ctx, _db = fresh_app

        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            "archive": {"Wgs.yaml": _test_yaml("1.2.0")}})

        assert ok, message
        (profile,) = ctx.test_profile_repo.list_all()
        assert profile.source_file == "Wgs.yaml"


class TestTheRepeatCheckWillNotRunOnListsOutOfStep:
    """The profiles and their paths are built side by side, and ``zip``
    without ``strict=True`` stops at the shorter one. A later caller that
    appended a profile without appending its path would drop the trailing
    profiles out of the repeat check, and a test and version in two files
    would sync silently -- the defect this item sits on (batch 4 review
    fix E)."""

    @staticmethod
    def _two_wgs_1_2():
        # Imported here: a module-level TestProfile would be collected by pytest.
        from seqsetup.models.test_profile import TestProfile
        return [TestProfile(test_type="WGS", version="1.2.0", source_file="Wgs.yaml"),
                TestProfile(test_type="WGS", version="1.2.0", source_file="Wgs.yaml")]

    def test_fewer_paths_than_profiles_raises_and_refuses_nothing_silently(self):
        refused: list[str] = []

        with pytest.raises(ValueError):
            GitHubSyncService._refuse_repeated_test_versions(
                self._two_wgs_1_2(), refused, ["a/Wgs.yaml"])

        assert refused == []

    def test_more_paths_than_profiles_raises(self):
        refused: list[str] = []

        with pytest.raises(ValueError):
            GitHubSyncService._refuse_repeated_test_versions(
                self._two_wgs_1_2()[:1], refused, ["a/Wgs.yaml", "b/Wgs.yaml"])

        assert refused == []

    def test_lists_in_step_still_name_both_paths(self):
        refused: list[str] = []

        GitHubSyncService._refuse_repeated_test_versions(
            self._two_wgs_1_2(), refused, ["a/Wgs.yaml", "b/Wgs.yaml"])

        assert refused == ["WGS 1.2.0 is in a/Wgs.yaml and b/Wgs.yaml"]

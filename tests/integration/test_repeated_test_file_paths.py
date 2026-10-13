"""The repeated-test refusal names each file by its path in the repository.

A test and version may be in one file only, and the refusal names the files
that hold it. It named them by base name, so two files in different folders
of the test-profile tree read as the same file -- "WGS 1.2.0 is in Wgs.yaml
and Wgs.yaml" -- and an admin had nothing to go on to find the second one.
"""

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

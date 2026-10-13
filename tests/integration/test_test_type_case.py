"""A config sync refuses two test profiles whose TestType differs only in
letter case.

``TestType`` is matched exactly, so ``Wgs`` and ``WGS`` are two tests: a
sample typed one way gets one set of application profiles and a sample typed
the other way gets the other, while every page and the Sample Sheet show what
a reader takes for the same test (noted in spec 2026-10-07 group A4, under
what it did not cover). Both files are refused, so no test profile is stored
and the stored ones are kept — group A4's refusal for one test and version in
two files.
"""

from .test_group_a4 import REFUSED, STORED_BEFORE, TESTS_BEFORE, _stored, _sync_tests, _test_yaml


class TestTwoTestsThatDifferOnlyInCapitals:
    def test_both_files_are_refused_and_nothing_is_stored(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message
        assert _stored(ctx) == STORED_BEFORE

        ok, message, logged = _sync_tests(ctx, monkeypatch, {
            "Wgs.yaml": _test_yaml("1.2.0", "Wgs"),
            "WGS.yaml": _test_yaml("1.2.0", "WGS"),
            "Rna.yaml": _test_yaml("1.0.0", "RNA"),
        })

        assert ok is False
        # WGS 1.1.0's file is not in this sync, so the refusal names it as
        # kept without being read (batch 4, item 11);
        # tests/integration/test_refused_sync_keeps_versions.py.
        assert message == (REFUSED + "WGS in WGS.yaml and Wgs in Wgs.yaml differ only in "
                           "capitals. Kept test profiles this sync did not read: WGS 1.1.0 "
                           "-- each is in a refused file or no longer in the repository. "
                           "Synced 1 application profiles.")
        assert ("Test profiles refused: WGS in WGS.yaml and Wgs in Wgs.yaml differ only in "
                "capitals. Two tests may not differ only in capitals.") in logged
        assert _stored(ctx) == STORED_BEFORE

    def test_three_spellings_are_all_named(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            "a.yaml": _test_yaml("1.0.0", "PAN"),
            "b.yaml": _test_yaml("1.0.0", "Pan"),
            "c.yaml": _test_yaml("1.0.0", "pan"),
        })

        assert ok is False
        assert message == (REFUSED + "PAN in a.yaml, Pan in b.yaml and pan in c.yaml differ "
                           "only in capitals. Synced 1 application profiles.")

    def test_every_file_of_a_spelling_is_named(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            "old.yaml": _test_yaml("1.0.0", "WGS"),
            "new.yaml": _test_yaml("1.1.0", "WGS"),
            "other.yaml": _test_yaml("1.0.0", "Wgs"),
        })

        assert ok is False
        assert message == (REFUSED + "WGS in new.yaml, old.yaml and Wgs in other.yaml differ "
                           "only in capitals. Synced 1 application profiles.")


class TestWhatIsStillAccepted:
    def test_one_spelling_in_several_files_is_fine(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            "Wgs_1.1.yaml": _test_yaml("1.1.0"), "Wgs_1.2.yaml": _test_yaml("1.2.0"),
        })

        assert ok, message
        assert _stored(ctx) == [("WGS", "1.1.0", "Wgs_1.1.yaml"), ("WGS", "1.2.0", "Wgs_1.2.yaml")]

    def test_two_different_tests_are_fine(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)

        assert ok, message
        assert _stored(ctx) == STORED_BEFORE

    def test_one_test_and_version_in_two_files_is_still_refused_its_own_way(
            self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, logged = _sync_tests(ctx, monkeypatch, {
            "Wgs_a.yaml": _test_yaml("1.2.0"), "Wgs_b.yaml": _test_yaml("1.2.0"),
        })

        assert ok is False
        assert message == (REFUSED + "WGS 1.2.0 is in Wgs_a.yaml and Wgs_b.yaml. "
                           "Synced 1 application profiles.")
        assert ("Test profiles refused: WGS 1.2.0 is in Wgs_a.yaml and Wgs_b.yaml. "
                "A test and version may be in one file only.") in logged

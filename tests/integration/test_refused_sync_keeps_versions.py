"""A refused sync names the stored test versions it kept but did not read.

A refused test-profile file means no test profile is stored and every stored
one is kept, including a version that was deliberately deleted from the
repository: the next sync of that repository would have removed it, and the
refusal keeps it instead. The message said which files were refused and what
it did sync, but nothing about the kept versions, so a lab that had removed a
version could not see from the page that it is still there -- and a sample
asking for that test can still resolve to it.
"""

from .test_group_a4 import TESTS_BEFORE, _sync_tests, _test_yaml

KEPT = "Kept test profiles this sync did not read: "
TAIL = " -- each is in a refused file or no longer in the repository."


class TestARefusedSyncNamesWhatItKept:
    def test_a_version_removed_from_the_repo_is_named(
            self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message

        # The repository now holds only WGS 1.1.0, plus one refused file.
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            "Wgs_1.1.yaml": _test_yaml("1.1.0"), "Bad.yaml": _test_yaml("1.0")})

        assert not ok
        assert KEPT + "RNA 1.0.0, WGS 1.2.0" + TAIL in message
        # Nothing was stored, so all three are still there.
        assert sorted((p.test_type, p.version) for p in ctx.test_profile_repo.list_all()) == [
            ("RNA", "1.0.0"), ("WGS", "1.1.0"), ("WGS", "1.2.0")]

    def test_a_refusal_that_read_every_stored_version_says_nothing_about_kept(
            self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message

        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            **TESTS_BEFORE, "Bad.yaml": _test_yaml("1.0")})

        assert not ok
        assert KEPT not in message

    def test_a_first_sync_that_is_refused_says_nothing_about_kept(
            self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, message, _logged = _sync_tests(ctx, monkeypatch, {"Bad.yaml": _test_yaml("1.0")})

        assert not ok
        assert KEPT not in message

    def test_a_sync_that_succeeds_says_nothing_about_kept(
            self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message

        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            "Wgs_1.1.yaml": _test_yaml("1.1.0")})

        assert ok, message
        assert KEPT not in message
        assert sorted((p.test_type, p.version) for p in ctx.test_profile_repo.list_all()) == [
            ("WGS", "1.1.0")]

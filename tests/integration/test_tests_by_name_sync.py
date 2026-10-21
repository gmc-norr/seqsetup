"""Several test profiles may share a TestType and a version: a test is its
TestName (the user's word, 2026-10-21;
docs/design/2026-10-21-tests-by-name-design.md). The lab's two WGS tests,
one per downstream pipeline, are both WGS 1.0.0."""

from .test_group_a4 import _sync_tests


def _named(name, version="1.0.0", test_type="WGS"):
    return (f"TestType: {test_type}\n"
            f"TestName: {name}\n"
            "Description: Whole genome\n"
            f'Version: "{version}"\n'
            "TestApplicationProfiles:\n"
            "  OnInstrument:\n"
            "    - ApplicationProfileName: GuardProfile\n"
            '      ApplicationProfileVersion: "1.0.0"\n')


LAB = {"WGSRareDisease_1.yaml": _named("WGSRareDisease_1"),
       "WGSRareDiseaseResearch_1.yaml": _named("WGSRareDiseaseResearch_1")}


def _stored(ctx):
    return sorted((p.test_name, p.test_type, p.version) for p in ctx.test_profile_repo.list_all())


class TestTwoTestsOfOneTypeAndVersion:

    def test_a_sync_stores_both(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, message, _logged = _sync_tests(ctx, monkeypatch, LAB)

        assert ok, message
        assert _stored(ctx) == [("WGSRareDiseaseResearch_1", "WGS", "1.0.0"),
                                ("WGSRareDisease_1", "WGS", "1.0.0")]

    def test_one_name_and_version_in_two_files_is_refused(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            "a.yaml": _named("Exome", test_type="WES"), "b.yaml": _named("Exome")})

        assert ok is False
        assert "Exome 1.0.0 is in" in message, message
        assert _stored(ctx) == []

    def test_a_refused_sync_names_the_tests_it_kept_by_name(self, fresh_app, monkeypatch):
        """Compared by TestType, the kept WGSRareDiseaseResearch_1 looked read
        because WGSRareDisease_1, of the same TestType and version, was."""
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, LAB)
        assert ok, message

        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            "WGSRareDisease_1.yaml": LAB["WGSRareDisease_1.yaml"], "Broken.yaml": "TestType: [\n"})

        assert ok is False
        assert ("Kept test profiles this sync did not read: WGSRareDiseaseResearch_1 1.0.0"
                in message), message
        assert len(_stored(ctx)) == 2

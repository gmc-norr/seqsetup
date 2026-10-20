"""The config sync reads the lab's one application profile folder, which also
holds profiles for other tools, and the lab's test profile layout
(docs/design/2026-10-19-lab-profile-layout-design.md)."""

from .test_group_a4 import _sync_tests, _test_yaml
from .test_sheet_followups import _app_profile_yaml

GUARD = _app_profile_yaml("GuardProfile", '"4.3.6"')
PIPELINE = (
    "ApplicationProfileName: NfCoreRareDisease\n"
    'ApplicationProfileVersion: "1.1"\n'
    "ApplicationType: nextflow\n"
    "ApplicationName: nf-core/raredisease\n"
    "Settings:\n"
    "  Version: 2.4.0\n"
    "  Profile: clinical\n"
)
TESTS = {"Wgs.yaml": _test_yaml("1.0.0")}
FOLDER = "profiles/application_profiles"
SKIPPED = ("Skipped 1 application profile file for other tools (its type is not Dragen): "
           f"{FOLDER}/NfCore.yaml (nextflow).")


def _stored_apps(ctx) -> list[str]:
    return sorted(p.name for p in ctx.app_profile_repo.list_all())


class TestProfilesForOtherToolsAreSkipped:
    """A profile whose type is not Dragen is not stored, and the sync says so."""

    def test_only_the_dragen_profile_is_stored(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS,
                                           {"Guard.yaml": GUARD, "NfCore.yaml": PIPELINE})
        assert ok, message
        assert _stored_apps(ctx) == ["GuardProfile"]
        assert SKIPPED in message

    def test_several_are_named_with_their_types(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        solid = PIPELINE.replace("NfCoreRareDisease", "GMSTwistSolid").replace("nextflow", "snakemake")
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS, {
            "Guard.yaml": GUARD, "NfCore.yaml": PIPELINE, "pipelines": {"Solid.yaml": solid}})
        assert ok, message
        assert ("Skipped 2 application profile files for other tools (its type is not Dragen): "
                f"{FOLDER}/NfCore.yaml (nextflow), {FOLDER}/pipelines/Solid.yaml (snakemake).") in message

    def test_at_most_20_are_named(self, fresh_app, monkeypatch):
        """A long list would be cut where the message is stored, under a
        marker that points at the list of problems, which skipped files are
        not in (fresh review of f54d3f0, P3 2)."""
        _app, ctx, _db = fresh_app
        pipelines = {f"P{n:02}.yaml": PIPELINE.replace("NfCoreRareDisease", f"P{n:02}") for n in range(25)}
        ok, message, logged = _sync_tests(ctx, monkeypatch, TESTS, {"Guard.yaml": GUARD, **pipelines})
        assert ok, message
        named = ", ".join(f"{FOLDER}/P{n:02}.yaml (nextflow)" for n in range(20))
        assert ("Skipped 25 application profile files for other tools (its type is not Dragen): "
                f"{named}, and 5 more, each named in the log.") in message
        assert f"Skipped {FOLDER}/P24.yaml: a profile for other tools" in logged

    def test_a_sync_that_skips_nothing_says_nothing_of_it(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS, {"Guard.yaml": GUARD})
        assert ok, message
        assert "Skipped" not in message

    def test_a_type_that_is_not_plain_text_is_not_quoted(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        odd = PIPELINE.replace("ApplicationType: nextflow", "ApplicationType: 'next flow, v2'")
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS,
                                           {"Guard.yaml": GUARD, "NfCore.yaml": odd})
        assert ok, message
        assert f"{FOLDER}/NfCore.yaml (another type)." in message


class TestAFolderOfOnlySkippedFiles:
    """The sync's guard against replacing stored profiles with nothing
    refuses it, so the stored profiles stay usable; it names the skipped
    files (sol's review of the design)."""

    def test_the_stored_profiles_stay(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS, {"Guard.yaml": GUARD})
        assert ok, message
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS, {"NfCore.yaml": PIPELINE})
        assert not ok
        assert _stored_apps(ctx) == ["GuardProfile"]
        assert "Refusing to replace 1 existing application profiles with 0 fetched items" in message
        assert ("Every application profile file was skipped, as one for other tools (its type is "
                f"not Dragen): {FOLDER}/NfCore.yaml (nextflow).") in message

    def test_a_seqsetup_with_none_stored_stores_none(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS, {"NfCore.yaml": PIPELINE})
        assert ok, message
        assert _stored_apps(ctx) == []
        assert SKIPPED in message


class TestRefusedFiles:
    """What the new rules refuse stops the sync for that kind of profile, as
    any refused file does."""

    def test_an_illumina_application_of_another_type(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        typo = GUARD.replace("ApplicationType: Dragen", "ApplicationType: BclConvert")
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS, {"Guard.yaml": typo})
        assert not ok
        assert (f"{FOLDER}/Guard.yaml:4:1: ApplicationType: must be Dragen: BCLConvert is one of "
                "Illumina's applications") in message
        assert _stored_apps(ctx) == []

    def test_a_test_file_in_the_old_layout(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        old = (_test_yaml("1.0.0").replace("TestApplicationProfiles:\n  OnInstrument:\n", "ApplicationProfiles:\n")
               .replace("    - ", "  - ").replace("      ApplicationProfileVersion", "    ApplicationProfileVersion"))
        ok, message, logged = _sync_tests(ctx, monkeypatch, {"Wgs.yaml": old}, {"Guard.yaml": GUARD})
        assert not ok
        assert "profiles/test_profiles/Wgs.yaml" in message
        # Every problem is logged and listed on the Config Sync page.
        assert any("Wgs.yaml:5:1: ApplicationProfiles: is no longer read: list these profiles under "
                   "TestApplicationProfiles > OnInstrument" in line for line in logged), logged
        assert list(ctx.test_profile_repo.list_all()) == []

    def test_a_test_file_with_downstream_analysis_is_stored(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        test = _test_yaml("1.0.0") + (
            "  DownstreamAnalysis:\n"
            "    - ApplicationProfileName: NfCoreRareDisease\n"
            "      ApplicationProfileVersion: 1\n"
            "      DependsOn: GuardProfile\n")
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {"Wgs.yaml": test},
                                           {"Guard.yaml": GUARD, "NfCore.yaml": PIPELINE})
        assert ok, message
        (stored,) = ctx.test_profile_repo.list_all()
        assert [(r.profile_name, r.profile_version) for r in stored.application_profiles] == [
            ("GuardProfile", "1.0.0")]

    def test_a_refusal_still_names_the_skipped_files(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {"Wgs.yaml": "TestType: 5\n"},
                                           {"Guard.yaml": GUARD, "NfCore.yaml": PIPELINE})
        assert not ok
        assert SKIPPED in message

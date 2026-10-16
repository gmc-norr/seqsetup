"""A config sync never replaces the stored application profiles with an
incomplete or ambiguous set (outside review of f490536, findings F1 and F10).

F1: an application-profile file or sub-folder the sync could not read was
logged and skipped, the rest were stored and the sync said "Synced", so a
"~=1.0.0" reference picked the older 1.0.0 without a word. F10: two files
giving one profile name and version were both stored, and a run got
whichever MongoDB returned first. Both now refuse the sync for application
profiles, name each file by its path, and keep the stored profiles, as a
refused test-profile file does (spec 2026-10-07 group A4, §1)."""

import pytest

from seqsetup.models.sequencing_run import RunStatus
from seqsetup.services.github_sync import GitHubSyncError

from .conftest import mark_ready, stored_export
from .test_group_a3 import ORIGIN, _indexed_draft
from .test_group_a4 import _fake_github, _test_yaml

ADAPTER = "CTGTCTCTTATACACATCT"


def _profile(version: str, software: str = '"4.3.6"', adapter: bool = False) -> str:
    """A BCLConvert application profile GuardProfile of ``version``; with
    ``adapter`` it carries AdapterRead1, so a sheet shows which file wrote it."""
    return (
        "ApplicationProfileName: GuardProfile\n"
        f'ApplicationProfileVersion: "{version}"\n'
        "ApplicationName: BCLConvert\n"
        "ApplicationType: BclConvert\n"
        "Settings:\n"
        f"  SoftwareVersion: {software}\n"
        + (f"  AdapterRead1: {ADAPTER}\n" if adapter else "")
        + "DataFields:\n"
        "  - Sample_ID\n"
        "  - Lane\n"
        "  - Index\n"
        "  - Index2\n"
        "  - OverrideCycles\n"
    )


OLD = _profile("1.0.0")
NEW = _profile("1.0.1", adapter=True)
# The shipped and documented reference form (config/profiles/test_profiles/Wgs.yaml).
COMPATIBLE_TESTS = {"Test.yaml": _test_yaml("1.0.0").replace(
    'ApplicationProfileVersion: "1.0.0"', 'ApplicationProfileVersion: "~=1.0.0"')}
EXACT_TESTS = {"Test.yaml": _test_yaml("1.0.0")}  # lists GuardProfile "1.0.0" exactly

# How the 1.0.1 file fails on the second sync: (application-profile folder,
# the file whose download fails, what the message must name).
UNREAD = [
    pytest.param({"old.yaml": OLD, "new.yaml": "broken: ["}, None, "new.yaml", id="not-yaml"),
    pytest.param({"old.yaml": OLD, "new.yaml": _profile("1.0.1", software="4.10", adapter=True)},
                 None, "new.yaml", id="fails-its-checks"),
    pytest.param({"old.yaml": OLD, "new.yaml": ""}, None, "new.yaml", id="empty"),
    pytest.param({"old.yaml": OLD, "new.yaml": None}, None, "new.yaml", id="no-download-link"),
    pytest.param({"old.yaml": OLD, "new.yaml": NEW}, "new.yaml", "new.yaml",
                 id="download-fails"),
    pytest.param({"v100": {"old.yaml": OLD},
                  "v101": GitHubSyncError("GitHub API error: 403 rate limit exceeded")},
                 None, "v101", id="sub-folder-cannot-be-listed"),
]


def _seed_instrument(ctx):
    from seqsetup.data import instruments as instruments_module
    from seqsetup.models.instrument_definition import InstrumentDefinition, OnboardApplication
    from seqsetup.services.validation import clear_validation_cache
    ctx.instrument_definition_repo.save(InstrumentDefinition(
        name="NovaSeq X Series", samplesheet_name="NovaSeqXSeries", version="1.0.0",
        chemistry_type="2-color",
        onboard_applications=[OnboardApplication(name="BCLConvert", software_version="4.3.6")],
        i5_workflows=[{"name": "Standard", "i5_read_orientation": "reverse-complement"}],
        runinfo_marks_i5_reversed=True,
    ))
    instruments_module.clear_synced_instruments_cache()
    clear_validation_cache()


def _sync_both_versions(ctx, monkeypatch, nested: bool = False):
    files = ({"v100": {"old.yaml": OLD}, "v101": {"new.yaml": NEW}} if nested
             else {"old.yaml": OLD, "new.yaml": NEW})
    ok, msg, _count = _fake_github(ctx, monkeypatch, COMPATIBLE_TESTS, app_files=files).sync()
    assert ok, msg
    assert ctx.app_profile_repo.get_by_name_version("GuardProfile", "~=1.0.0").version == "1.0.1"


def _sync_again(ctx, monkeypatch, app_files, refuse_download=None, tests=COMPATIBLE_TESTS):
    service = _fake_github(ctx, monkeypatch, tests, app_files=app_files)
    if refuse_download:
        fetch = service._fetch_file_content

        def flaky(url):
            if url.endswith(refuse_download):
                raise GitHubSyncError("Failed to fetch file: 503 Service Unavailable")
            return fetch(url)

        monkeypatch.setattr(service, "_fetch_file_content", flaky)
    return service.sync()


class TestAnUnreadApplicationProfileFileRefusesTheSync:
    """Any application-profile file or sub-folder that gives no profile stops
    every application-profile change: the sync says so, names it, and the
    stored profiles stay, so "~=1.0.0" still picks 1.0.1."""

    @pytest.mark.parametrize("app_files,refuse_download,named", UNREAD)
    def test_sync_refuses_and_keeps_the_stored_profiles(self, fresh_app, monkeypatch,
                                                        app_files, refuse_download, named):
        _app, ctx, _db = fresh_app
        _sync_both_versions(ctx, monkeypatch, nested=isinstance(app_files.get("v101"), Exception))

        ok, msg, _count = _sync_again(ctx, monkeypatch, app_files, refuse_download)

        picked = ctx.app_profile_repo.get_by_name_version("GuardProfile", "~=1.0.0")
        stored = sorted(p.version for p in ctx.app_profile_repo.get_by_name("GuardProfile"))
        assert not ok, f"sync reported success: {msg!r}; ~=1.0.0 now picks {picked.version}"
        assert named in msg, msg
        assert "application profile" in msg.lower(), msg
        assert stored == ["1.0.0", "1.0.1"]
        assert picked.version == "1.0.1"
        assert ctx.profile_sync_config_repo.get().last_sync_status == "error"

    def test_test_profiles_are_still_stored(self, fresh_app, monkeypatch):
        """Only the application profiles are kept: the test profiles the sync
        read are stored, as the application profiles are when a test file is
        refused."""
        _app, ctx, _db = fresh_app
        _sync_both_versions(ctx, monkeypatch)
        tests = {"Test.yaml": COMPATIBLE_TESTS["Test.yaml"],
                 "Test2.yaml": _test_yaml("1.0.0", test="WES").replace(
                     'ApplicationProfileVersion: "1.0.0"', 'ApplicationProfileVersion: "~=1.0.0"')}

        ok, msg, _count = _sync_again(ctx, monkeypatch, {"old.yaml": OLD, "new.yaml": ""},
                                      tests=tests)

        assert not ok
        assert sorted(p.test_type for p in ctx.test_profile_repo.list_all()) == ["WES", "WGS"]

    def test_message_names_the_stored_versions_it_did_not_read(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _sync_both_versions(ctx, monkeypatch)

        ok, msg, _count = _sync_again(ctx, monkeypatch, {"old.yaml": OLD, "new.yaml": "broken: ["})

        assert not ok
        assert "GuardProfile 1.0.1" in msg, msg

    def test_a_readable_set_still_syncs(self, fresh_app, monkeypatch):
        """Control: with every file readable the sync stores them and says so."""
        _app, ctx, _db = fresh_app
        _sync_both_versions(ctx, monkeypatch)

        ok, msg, _count = _sync_again(ctx, monkeypatch, {"old.yaml": OLD})

        assert ok, msg
        assert [p.version for p in ctx.app_profile_repo.get_by_name("GuardProfile")] == ["1.0.0"]


class TestOneNameAndVersionInTwoFilesIsRefused:
    """Every file of a repeated name and version is refused and named by its
    path; no application profile changes, so the one stored before stays."""

    REAL = _profile("1.0.0", adapter=True)     # the file the lab uses
    COPY = _profile("1.0.0", adapter=False)    # a copy edited without a new version

    @pytest.mark.parametrize("app_files,paths", [
        pytest.param({"a_copy.yaml": COPY, "guard.yaml": REAL}, ("a_copy.yaml", "guard.yaml"),
                     id="one-folder"),
        pytest.param({"archive": {"guard.yaml": COPY}, "dragen": {"guard.yaml": REAL}},
                     ("archive/guard.yaml", "dragen/guard.yaml"),
                     id="same-base-name-two-folders"),
    ])
    def test_sync_refuses_and_keeps_the_stored_profile(self, fresh_app, monkeypatch,
                                                       app_files, paths):
        _app, ctx, _db = fresh_app
        ok, msg, _count = _fake_github(ctx, monkeypatch, EXACT_TESTS,
                                       app_files={"guard.yaml": self.REAL}).sync()
        assert ok, msg

        ok, msg, _count = _fake_github(ctx, monkeypatch, EXACT_TESTS, app_files=app_files).sync()

        stored = ctx.app_profile_repo.get_by_name("GuardProfile")
        picked = ctx.app_profile_repo.get_by_name_version("GuardProfile", "1.0.0")
        assert not ok, (f"sync reported success: {msg!r}; {len(stored)} GuardProfile 1.0.0 "
                        f"stored, 1.0.0 picks {picked.source_file}")
        for path in paths:
            assert path in msg, msg
        assert len(stored) == 1
        assert picked.settings.get("AdapterRead1") == ADAPTER

    def test_two_spellings_of_one_version_are_one_version(self, fresh_app, monkeypatch):
        """ "1.0" and "1.0.0" are one version: "~=1.0" matches both."""
        _app, ctx, _db = fresh_app
        tests = {"Test.yaml": _test_yaml("1.0.0").replace(
            'ApplicationProfileVersion: "1.0.0"', 'ApplicationProfileVersion: "~=1.0"')}

        ok, msg, _count = _fake_github(ctx, monkeypatch, tests, app_files={
            "a.yaml": _profile("1.0"), "b.yaml": _profile("1.0.0", adapter=True),
        }).sync()

        assert not ok, msg
        assert "a.yaml" in msg and "b.yaml" in msg, msg
        assert ctx.app_profile_repo.list_all() == []

    def test_another_name_or_version_is_not_a_repeat(self, fresh_app, monkeypatch):
        """Control: one name in two versions, and two names in one version, sync."""
        _app, ctx, _db = fresh_app
        other = self.REAL.replace("GuardProfile", "OtherProfile")

        ok, msg, _count = _fake_github(ctx, monkeypatch, EXACT_TESTS, app_files={
            "a.yaml": OLD, "b.yaml": NEW, "c.yaml": other,
        }).sync()

        assert ok, msg
        assert len(ctx.app_profile_repo.list_all()) == 3


class TestTheSheetAfterARefusedSync:
    """End to end: a run marked Ready after a refused sync is written with the
    profile stored before, never with an older or a copied one."""

    def test_unread_newest_file_keeps_the_newest_profile(self, fresh_app, logged_in_client,
                                                         monkeypatch):
        _app, ctx, _db = fresh_app
        _seed_instrument(ctx)
        _sync_both_versions(ctx, monkeypatch)
        _sync_again(ctx, monkeypatch, {"old.yaml": OLD, "new.yaml": NEW},
                    refuse_download="new.yaml")

        run = _indexed_draft(ctx, "f1-sheet", test_id="WGS", test_version="1")
        resp = mark_ready(logged_in_client, run.id, ORIGIN)
        stored = ctx.run_repo.get_by_id(run.id)

        assert stored.status == RunStatus.READY, resp.text[:2000]
        sheet = stored_export(ctx, stored, "samplesheet_v2")
        assert ADAPTER in sheet, sheet

    def test_copied_file_keeps_the_profile_stored_before(self, fresh_app, logged_in_client,
                                                         monkeypatch):
        _app, ctx, _db = fresh_app
        _seed_instrument(ctx)
        real = _profile("1.0.0", adapter=True)
        ok, msg, _count = _fake_github(ctx, monkeypatch, EXACT_TESTS,
                                       app_files={"guard.yaml": real}).sync()
        assert ok, msg
        _fake_github(ctx, monkeypatch, EXACT_TESTS, app_files={
            "a_copy.yaml": _profile("1.0.0"), "guard.yaml": real}).sync()

        run = _indexed_draft(ctx, "f10-sheet", test_id="WGS", test_version="1")
        resp = mark_ready(logged_in_client, run.id, ORIGIN)
        stored = ctx.run_repo.get_by_id(run.id)

        assert stored.status == RunStatus.READY, resp.text[:2000]
        sheet = stored_export(ctx, stored, "samplesheet_v2")
        assert ADAPTER in sheet, sheet


class TestARefusedNewProfileIsNotFound:
    """A refused file of a profile that was never stored is as if it were not
    synced yet: the stored ones stay, and a run that needs it is refused at
    Mark Ready, naming it (the fresh review of 06e765e, P3 6)."""

    def test_mark_ready_says_the_profile_is_not_found(self, fresh_app, logged_in_client,
                                                      monkeypatch):
        _app, ctx, _db = fresh_app
        _seed_instrument(ctx)
        other = _profile("1.0.0", adapter=True).replace("GuardProfile", "OtherProfile")
        ok, msg, _count = _fake_github(ctx, monkeypatch, EXACT_TESTS,
                                       app_files={"other.yaml": other}).sync()
        assert ok, msg

        ok, msg, _count = _fake_github(ctx, monkeypatch, EXACT_TESTS, app_files={
            "other.yaml": other, "guard.yaml": "broken: ["}).sync()
        assert not ok, msg

        run = _indexed_draft(ctx, "refused-new", test_id="WGS", test_version="1")
        resp = mark_ready(logged_in_client, run.id, ORIGIN)

        assert "GuardProfile" in resp.text and "not found" in resp.text, resp.text[:2000]
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT


class TestAProfileNameMustBeText:
    """A profile name that YAML reads as a list or a number is refused and
    named: it is how a reference finds the profile, and a stored list once
    answered a reference to any name in it (the fresh review of 06e765e, P3 1)."""

    @pytest.mark.parametrize("name", ["[GuardProfile, OtherProfile]", "{a: b}", "123"])
    def test_sync_refuses_the_file(self, fresh_app, monkeypatch, name):
        _app, ctx, _db = fresh_app
        odd = OLD.replace("ApplicationProfileName: GuardProfile",
                          f"ApplicationProfileName: {name}")

        ok, msg, _count = _fake_github(ctx, monkeypatch, EXACT_TESTS,
                                       app_files={"old.yaml": OLD, "odd.yaml": odd}).sync()

        assert not ok, msg
        assert "odd.yaml" in msg and "'ApplicationProfileName' must be text" in msg, msg
        assert ctx.app_profile_repo.list_all() == []
        assert [p.test_type for p in ctx.test_profile_repo.list_all()] == ["WGS"]

    def test_a_quoted_number_is_text(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        quoted = OLD.replace("ApplicationProfileName: GuardProfile",
                             'ApplicationProfileName: "123"')

        ok, msg, _count = _fake_github(ctx, monkeypatch, EXACT_TESTS,
                                       app_files={"old.yaml": quoted}).sync()

        assert ok, msg
        assert [p.name for p in ctx.app_profile_repo.list_all()] == ["123"]


class TestTheRefusalMessage:
    """What the sync says when application profiles are refused (the fresh
    review of 06e765e, P3 4 and 5)."""

    def test_a_file_that_is_not_a_mapping_says_so(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, msg, _count = _fake_github(ctx, monkeypatch, EXACT_TESTS, app_files={
            "old.yaml": OLD, "list.yaml": "- GuardProfile\n- 1.0.0\n"}).sync()

        assert not ok
        assert "list.yaml: is not a profile: YAML read it as a list, not a mapping" in msg, msg

    def test_nothing_synced_says_no_synced_part(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, msg, _count = _fake_github(ctx, monkeypatch, {**EXACT_TESTS, "Empty.yaml": ""},
                                       app_files={"old.yaml": OLD, "new.yaml": ""}).sync()

        assert not ok
        assert "Synced" not in msg, msg
        assert msg.endswith("."), msg

    def test_a_pause_left_by_an_earlier_sync_says_fix_the_files(self, fresh_app, monkeypatch):
        from seqsetup.utils.clock import utcnow
        _app, ctx, _db = fresh_app
        _sync_both_versions(ctx, monkeypatch)
        ctx.profile_sync_config_repo.mark_writing(utcnow(), "application profiles")

        ok, msg, _count = _sync_again(ctx, monkeypatch, {"old.yaml": OLD, "new.yaml": ""})

        assert not ok
        assert "Mark Ready stays paused" in msg, msg
        assert "Fix the refused files, then sync again." in msg, msg

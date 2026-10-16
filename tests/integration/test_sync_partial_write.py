"""A config sync that stops while it is writing pauses Mark Ready (outside
review of 7f858e0, finding 4; the user's choice "Pause Mark Ready",
2026-10-14).

A sync deletes the stored profiles and instrument records, then writes the
new ones one at a time; MongoDB here is a single server, so the writes cannot
be one step. A write that fails part-way leaves a collection empty or partly
written: a sample's "1" could then pick an older test version, and an empty
instrument collection falls back to the shipped file, which can turn the i5
round. So the sync notes that it is writing before its first delete and
clears the note after its last write; while the note is there, Mark Ready
refuses every run. Each test injects a MongoDB failure into one save; only
the GitHub fetches are faked.
"""

import html
import re
import threading

from pymongo.errors import AutoReconnect

from seqsetup.models.sequencing_run import RunStatus
from seqsetup.services import github_sync
from seqsetup.utils.clock import local_time

from .conftest import disable_repos, mark_ready, nothing_stored, stored_export
from .test_group_a3 import ORIGIN, _indexed_draft
from .test_group_a4 import _fake_github, _test_yaml
from .test_scheduled_sync_instrument_cache import _scheduled_sync, _seed_run


def _profile_yaml(name: str, adapter: str) -> str:
    return (
        f"ApplicationProfileName: {name}\n"
        'ApplicationProfileVersion: "1.0.0"\n'
        "ApplicationName: BCLConvert\n"
        "ApplicationType: BclConvert\n"
        "Settings:\n"
        '  SoftwareVersion: "4.3.6"\n'
        f"  AdapterRead1: {adapter}\n"
        "DataFields:\n"
        "  - Sample_ID\n"
        "  - Lane\n"
        "  - Index\n"
        "  - Index2\n"
        "  - OverrideCycles\n"
    )


def _wgs_yaml(version: str, profile: str) -> str:
    return (
        "TestType: WGS\n"
        "TestName: WGS\n"
        "Description: Whole genome\n"
        f'Version: "{version}"\n'
        "ApplicationProfiles:\n"
        f"  - ApplicationProfileName: {profile}\n"
        '    ApplicationProfileVersion: "1.0.0"\n'
    )


OLD_ADAPTER = "AAAAAAAAAA"
NEW_ADAPTER = "CCCCCCCCCC"
APP_FILES = {"Old.yaml": _profile_yaml("OldProfile", OLD_ADAPTER),
             "New.yaml": _profile_yaml("NewProfile", NEW_ADAPTER)}
# Saved in this order: 1.1.0 first, then 1.2.0.
TEST_FILES = {"Wgs_1.1.yaml": _wgs_yaml("1.1.0", "OldProfile"),
              "Wgs_1.2.yaml": _wgs_yaml("1.2.0", "NewProfile")}

PAUSED_IN_STATUS = ("The settings were only partly written, so Mark Ready is paused "
                    "until a sync writes them again.")
SETTINGS_CHANGED = (
    "The profiles or instrument settings changed while the exports were being generated, so "
    "the Sample Sheet might not match what was checked. The run is still a Draft. Mark it "
    "Ready again.")


def _paused(since, what) -> str:
    return (f"A configuration sync started at {local_time(since)} did not finish writing the "
            f"{what}, so they may be incomplete. Mark Ready is paused until a sync writes them "
            "again. If a sync is running now, try again in a minute; otherwise an admin can "
            "press Sync now on the Config Sync page.")


def _still_paused(what) -> str:
    return (f"Mark Ready stays paused: a sync that stopped earlier left the {what} incomplete, "
            "and this sync did not write them again.")


def _sync(ctx, monkeypatch, test_files=None):
    service = _fake_github(ctx, monkeypatch, dict(test_files or TEST_FILES),
                           app_files=dict(APP_FILES))
    return service.sync()


def _fail_save(monkeypatch, repo, when=lambda item: True):
    """Make ``repo.save`` raise a MongoDB connection error for the items
    ``when`` picks; bulk_save calls save once per item."""
    original = repo.save

    def save(item):
        if when(item):
            raise AutoReconnect("connection reset by peer (injected)")
        return original(item)

    monkeypatch.setattr(repo, "save", save)
    return lambda: monkeypatch.setattr(repo, "save", original)


def _wgs_draft(ctx, run_id):
    return _indexed_draft(ctx, run_id, test_id="WGS", test_version="1")


def _reasons(ctx):
    return [e.details.get("reason")
            for e in ctx.audit_event_repo.search(limit=50, event_prefix="run.status.denied")]


def _refused_while_paused(client, ctx, run_id, what):
    resp = mark_ready(client, run_id, ORIGIN)
    since = ctx.profile_sync_config_repo.writing_since()
    assert since is not None
    assert resp.status_code == 409, html.unescape(resp.text)[:300]
    assert _paused(since, what) in html.unescape(resp.text)
    run = ctx.run_repo.get_by_id(run_id)
    assert run.status == RunStatus.DRAFT
    assert nothing_stored(ctx, run)
    assert "config_sync_unfinished" in _reasons(ctx)


class TestASyncThatStopsWhileWritingPausesMarkReady:

    def test_a_failed_application_profile_write(self, fresh_app, logged_in_client, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        run = _wgs_draft(ctx, "sync-app-write")

        _fail_save(monkeypatch, ctx.get_github_sync_service().app_profile_repo)
        ok, message, _ = _sync(ctx, monkeypatch)

        assert ok is False
        assert message.endswith(PAUSED_IN_STATUS), message
        assert ctx.profile_sync_config_repo.get().last_sync_message.endswith(PAUSED_IN_STATUS)
        _refused_while_paused(logged_in_client, ctx, run.id, "application profiles")

    def test_a_partly_written_test_profile_set(self, fresh_app, logged_in_client, monkeypatch):
        """Only WGS 1.1.0 is written: a sample asking for "1" would get it."""
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        run = _wgs_draft(ctx, "sync-test-write")

        _fail_save(monkeypatch, ctx.get_github_sync_service().test_profile_repo,
                   when=lambda profile: profile.version == "1.2.0")
        ok, _message, _ = _sync(ctx, monkeypatch)

        assert ok is False
        assert sorted(p.version for p in ctx.test_profile_repo.list_all()) == ["1.1.0"]
        _refused_while_paused(logged_in_client, ctx, run.id,
                              "application profiles and test profiles")

    def test_a_failed_test_profile_write_after_refused_application_profiles(
            self, fresh_app, logged_in_client, monkeypatch):
        """With the application profiles refused, the test profiles are the
        first collection written; their failed write still says Mark Ready
        is paused (outside review of f490536, F1)."""
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        run = _wgs_draft(ctx, "sync-test-write-apps-refused")

        _fail_save(monkeypatch, ctx.get_github_sync_service().test_profile_repo)
        ok, message, _ = _fake_github(ctx, monkeypatch, dict(TEST_FILES),
                                      app_files={**APP_FILES, "Bad.yaml": ""}).sync()

        assert ok is False
        assert message.endswith(PAUSED_IN_STATUS), message
        _refused_while_paused(logged_in_client, ctx, run.id, "test profiles")

    def test_a_failed_instrument_write_after_refused_profiles(
            self, fresh_app, logged_in_client, monkeypatch):
        """With both profile kinds refused, the instruments are the first
        collection written; their failed write still says Mark Ready is
        paused."""
        from .test_group_a2 import GOOD_FILES
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        run = _wgs_draft(ctx, "sync-instrument-write-profiles-refused")

        _fail_save(monkeypatch, ctx.get_github_sync_service().instrument_definition_repo)
        ok, message, _ = _fake_github(
            ctx, monkeypatch, {**TEST_FILES, "Empty.yaml": ""},
            app_files={**APP_FILES, "Bad.yaml": ""}, instrument_files=GOOD_FILES).sync()

        assert ok is False
        assert message.endswith(PAUSED_IN_STATUS), message
        _refused_while_paused(logged_in_client, ctx, run.id, "instrument settings")

    def test_a_failed_instrument_write(self, fresh_app, logged_in_client, monkeypatch):
        """The stored instruments are gone, so the shipped file would turn
        the i5 round."""
        _app, ctx, _db = fresh_app
        _scheduled_sync(ctx, monkeypatch, "reverse-complement")

        _fail_save(monkeypatch, ctx.get_github_sync_service().instrument_definition_repo)
        resp = logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN)
        assert resp.status_code == 200
        assert ctx.instrument_definition_repo.collection.count_documents({}) == 0

        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "sync-instrument-write")
        _refused_while_paused(logged_in_client, ctx, run_id,
                              "application profiles, test profiles and instrument settings")


class TestThePauseEnds:

    def test_the_next_sync_that_finishes_lifts_it(self, fresh_app, logged_in_client, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        run = _wgs_draft(ctx, "sync-lifted")
        restore = _fail_save(monkeypatch, ctx.get_github_sync_service().app_profile_repo)
        ok, _message, _ = _sync(ctx, monkeypatch)
        assert ok is False
        restore()

        ok, message, _ = _sync(ctx, monkeypatch)

        assert ok, message
        assert ctx.profile_sync_config_repo.writing_since() is None
        resp = mark_ready(logged_in_client, run.id, ORIGIN)
        assert resp.status_code == 200, html.unescape(resp.text)[:300]
        assert NEW_ADAPTER in stored_export(ctx, run.id, "samplesheet_v2")

    def test_a_sync_whose_files_are_refused_does_not_pause(
            self, fresh_app, logged_in_client, monkeypatch):
        """A refused test file keeps the stored tests; every write it made
        finished, so nothing is paused."""
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        run = _wgs_draft(ctx, "sync-refused")

        ok, message, _ = _sync(ctx, monkeypatch,
                               test_files={**TEST_FILES, "Wgs_bad.yaml": _test_yaml("1.0")})

        assert ok is False
        assert message.startswith("Test profile files were refused"), message
        assert PAUSED_IN_STATUS not in message
        assert ctx.profile_sync_config_repo.writing_since() is None
        resp = mark_ready(logged_in_client, run.id, ORIGIN)
        assert resp.status_code == 200, html.unescape(resp.text)[:300]


class TestASyncThatStopsBeforeWriting:

    def test_does_not_pause(self, fresh_app, logged_in_client, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        run = _wgs_draft(ctx, "sync-fetch-failed")

        service = _fake_github(ctx, monkeypatch, dict(TEST_FILES), app_files=dict(APP_FILES))

        def unreachable(*_args, **_kwargs):
            raise github_sync.GitHubSyncError("GitHub could not be reached")

        monkeypatch.setattr(service, "_fetch_profiles_recursive", unreachable)
        ok, message, _ = service.sync()

        assert ok is False
        assert "GitHub could not be reached" in message
        assert PAUSED_IN_STATUS not in message
        assert ctx.profile_sync_config_repo.writing_since() is None
        resp = mark_ready(logged_in_client, run.id, ORIGIN)
        assert resp.status_code == 200, html.unescape(resp.text)[:300]


class TestThePauseIsKeptApart:

    def test_saving_the_sync_settings_keeps_it(self, fresh_app, logged_in_client, monkeypatch):
        """The settings form saves the whole settings record; the pause is
        not part of it."""
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        run = _wgs_draft(ctx, "sync-settings-saved")
        _fail_save(monkeypatch, ctx.get_github_sync_service().app_profile_repo)
        ok, _message, _ = _sync(ctx, monkeypatch)
        assert ok is False

        config = ctx.profile_sync_config_repo.get()
        config.sync_interval_minutes = 30
        ctx.profile_sync_config_repo.save(config)

        _refused_while_paused(logged_in_client, ctx, run.id, "application profiles")


class TestMarkReadyChecksAgainBeforeSaving:

    def test_a_sync_that_starts_writing_during_the_exports(
            self, fresh_app, logged_in_client, monkeypatch):
        from seqsetup.routes import runs
        from seqsetup.utils.clock import utcnow
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        run = _wgs_draft(ctx, "sync-during-export")
        original = runs._pregenerate_exports

        def exports_then_a_sync_starts(*args, **kwargs):
            made = original(*args, **kwargs)
            ctx.profile_sync_config_repo.mark_writing(utcnow(), "test profiles")
            return made

        monkeypatch.setattr(runs, "_pregenerate_exports", exports_then_a_sync_starts)
        _refused_while_paused(logged_in_client, ctx, run.id, "test profiles")

    def test_a_sync_that_starts_and_finishes_during_mark_ready(
            self, fresh_app, logged_in_client, monkeypatch):
        """The sync starts writing just after the first check and finishes
        before the second: the note is gone at both, but the checks and the
        exports read WGS 1.1.0 alone (review P2-1)."""
        from seqsetup.routes import runs
        from seqsetup.services.validation import clear_validation_cache
        from seqsetup.utils.clock import utcnow
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        run = _wgs_draft(ctx, "sync-inside-mark-ready")
        coll = ctx.test_profile_repo.collection
        held = {}
        first_check = runs._refused_while_a_sync_is_writing

        def first_check_then_a_sync_starts(*args, **kwargs):
            first_check(*args, **kwargs)
            if not held:
                clear_validation_cache()
                ctx.profile_sync_config_repo.mark_writing(utcnow(), "test profiles")
                held["doc"] = coll.find_one({"version": "1.2.0"})
                coll.delete_one({"_id": held["doc"]["_id"]})

        original = runs._pregenerate_exports

        def exports_then_the_sync_finishes(*args, **kwargs):
            made = original(*args, **kwargs)
            coll.insert_one(held["doc"])
            clear_validation_cache()
            ctx.profile_sync_config_repo.written(["test profiles"])
            return made

        # The one-sample lane asks about color balance first; answer it once
        # the sync is in place, so only the request that writes is affected.
        asked = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)
        assert "Mark Ready anyway" in asked.text
        answers = dict(re.findall(r'name="(color_balance_[a-z_]+)" value="([^"]*)"', asked.text))
        monkeypatch.setattr(runs, "_refused_while_a_sync_is_writing",
                            first_check_then_a_sync_starts)
        monkeypatch.setattr(runs, "_pregenerate_exports", exports_then_the_sync_finishes)
        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", data=answers, headers=ORIGIN)

        assert held, "the sync never started"
        assert ctx.profile_sync_config_repo.writing_since() is None
        assert resp.status_code == 409, html.unescape(resp.text)[:300]
        assert SETTINGS_CHANGED in html.unescape(resp.text)
        stored = ctx.run_repo.get_by_id(run.id)
        assert stored.status == RunStatus.DRAFT
        assert nothing_stored(ctx, stored)
        assert "settings_changed_during_export" in _reasons(ctx)


class TestALaterSyncMustWriteWhatWasLeftIncomplete:
    """A sync that finishes lifts the pause only for what it wrote again
    (review P1-1)."""

    def _partial_tests(self, ctx, monkeypatch):
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        run = _wgs_draft(ctx, "sync-left-incomplete")
        restore = _fail_save(monkeypatch, ctx.get_github_sync_service().test_profile_repo,
                             when=lambda p: p.version == "1.2.0")
        ok, _message, _ = _sync(ctx, monkeypatch)
        assert ok is False
        restore()
        assert sorted(p.version for p in ctx.test_profile_repo.list_all()) == ["1.1.0"]
        return run

    def test_a_refused_test_file_keeps_it(self, fresh_app, logged_in_client, monkeypatch):
        _app, ctx, _db = fresh_app
        run = self._partial_tests(ctx, monkeypatch)

        ok, message, _ = _sync(ctx, monkeypatch,
                               test_files={**TEST_FILES, "Wgs_bad.yaml": _test_yaml("1.0")})

        assert ok is False
        assert message.startswith("Test profile files were refused"), message
        assert _still_paused("test profiles") + " Fix the refused files, then sync again." in message
        _refused_while_paused(logged_in_client, ctx, run.id, "test profiles")

    def test_a_test_folder_that_cannot_be_listed_keeps_it(
            self, fresh_app, logged_in_client, monkeypatch):
        _app, ctx, _db = fresh_app
        run = self._partial_tests(ctx, monkeypatch)

        ok, _message, _ = _sync(ctx, monkeypatch, test_files={
            **TEST_FILES, "more": github_sync.GitHubSyncError("GitHub API error: 502 Bad Gateway")})

        assert ok is False
        _refused_while_paused(logged_in_client, ctx, run.id, "test profiles")

    def test_switching_instrument_sync_off_keeps_it(
            self, fresh_app, logged_in_client, monkeypatch):
        _app, ctx, _db = fresh_app
        _scheduled_sync(ctx, monkeypatch, "reverse-complement")
        restore = _fail_save(monkeypatch,
                             ctx.get_github_sync_service().instrument_definition_repo)
        logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN)
        restore()
        assert ctx.instrument_definition_repo.collection.count_documents({}) == 0
        config = ctx.profile_sync_config_repo.get()
        config.sync_instruments_enabled = False
        ctx.profile_sync_config_repo.save(config)

        logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN)

        status = ctx.profile_sync_config_repo.get()
        assert status.last_sync_status == "error"
        assert (_still_paused("instrument settings")
                + " Switch on Also sync instruments, then sync again.") in status.last_sync_message
        page = html.unescape(logged_in_client.get("/admin/config-sync").text)
        assert ("did not finish writing the instrument settings. Switch on Also sync "
                "instruments, then press Sync now to write them again.") in page
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "sync-instruments-off")
        _refused_while_paused(logged_in_client, ctx, run_id, "instrument settings")

    def test_writing_the_instruments_again_lifts_it(
            self, fresh_app, logged_in_client, monkeypatch):
        _app, ctx, _db = fresh_app
        _scheduled_sync(ctx, monkeypatch, "reverse-complement")
        restore = _fail_save(monkeypatch,
                             ctx.get_github_sync_service().instrument_definition_repo)
        logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN)
        restore()
        assert ctx.profile_sync_config_repo.writing_since() is not None

        logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN)

        assert ctx.profile_sync_config_repo.get().last_sync_status == "success"
        assert ctx.profile_sync_config_repo.writing_since() is None
        assert ctx.instrument_definition_repo.collection.count_documents({}) == 1


class TestAFailedDeleteOrKitWrite:

    def test_a_failed_delete_pauses(self, fresh_app, logged_in_client, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        run = _wgs_draft(ctx, "sync-delete-failed")
        repo = ctx.get_github_sync_service().app_profile_repo

        def delete_all():
            raise AutoReconnect("connection reset by peer (injected)")

        monkeypatch.setattr(repo, "delete_all", delete_all)
        ok, message, _ = _sync(ctx, monkeypatch)

        assert ok is False and message.endswith(PAUSED_IN_STATUS), message
        _refused_while_paused(logged_in_client, ctx, run.id, "application profiles")

    def test_a_failed_kit_write_pauses_until_a_sync_finishes(self, fresh_app, monkeypatch):
        """The kits are written last; the profiles before them are not
        counted as written until the whole sync finishes."""
        from .test_synced_kit_indexes import GOOD_KIT_YAML, _sync_with_kits
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync_with_kits(ctx, monkeypatch, {"Kit.yaml": GOOD_KIT_YAML})
        assert ok, message
        restore = _fail_save(monkeypatch, ctx.index_kit_repo)

        ok, message, _ = _sync_with_kits(ctx, monkeypatch, {"Kit.yaml": GOOD_KIT_YAML})

        assert ok is False and message.endswith(PAUSED_IN_STATUS), message
        assert ctx.profile_sync_config_repo.writing_since() is not None
        restore()
        ok, message, _ = _sync_with_kits(ctx, monkeypatch, {"Kit.yaml": GOOD_KIT_YAML})
        assert ok, message
        assert ctx.profile_sync_config_repo.writing_since() is None


class TestADisabledInstrumentStaysDisabled:

    def test_after_a_sync_that_stopped_before_writing_it(self, fresh_app, monkeypatch):
        """The switch is read from the stored records just before they are
        replaced; a sync that stopped after deleting them must not lose it
        (review P2-2)."""
        from seqsetup.models.instrument_definition import InstrumentDefinition
        from .test_scheduled_sync_instrument_cache import _instrument
        _app, ctx, _db = fresh_app

        def other():
            return InstrumentDefinition(
                name="Other", samplesheet_name="OtherSeq", version="1.0.0",
                chemistry_type="2-color",
                i5_workflows=[{"name": "Standard", "i5_read_orientation": "forward"}],
                runinfo_marks_i5_reversed=False)

        config = ctx.profile_sync_config_repo.get()
        config.github_repo_url = "https://github.com/example/config"
        config.sync_instruments_enabled = True
        config.sync_index_kits_enabled = False
        ctx.profile_sync_config_repo.save(config)
        service = ctx.get_github_sync_service()
        monkeypatch.setattr(service, "_fetch_profiles_recursive", lambda *a, **k: [])
        monkeypatch.setattr(service, "_fetch_instruments",
                            lambda *a, **k: ([_instrument("forward"), other()], []))
        assert service.sync()[0]
        repo = ctx.instrument_definition_repo
        assert repo.set_enabled_by_name("Other", False)
        restore = _fail_save(monkeypatch, service.instrument_definition_repo,
                             when=lambda inst: inst.name == "Other")
        assert service.sync()[0] is False
        restore()

        assert service.sync()[0]

        assert repo.get_by_name("Other").enabled is False

    def test_an_instrument_switched_back_on_during_the_pause_stays_on(
            self, fresh_app, monkeypatch):
        """A noted switch counts only for an instrument the stopped sync did
        not write again; one it wrote carries the admin's switch (second
        review P3-1)."""
        from seqsetup.models.instrument_definition import InstrumentDefinition
        from .test_scheduled_sync_instrument_cache import _instrument
        _app, ctx, _db = fresh_app

        def named(name, samplesheet_name):
            return InstrumentDefinition(
                name=name, samplesheet_name=samplesheet_name, version="1.0.0",
                chemistry_type="2-color",
                i5_workflows=[{"name": "Standard", "i5_read_orientation": "forward"}],
                runinfo_marks_i5_reversed=False)

        config = ctx.profile_sync_config_repo.get()
        config.github_repo_url = "https://github.com/example/config"
        config.sync_instruments_enabled = True
        config.sync_index_kits_enabled = False
        ctx.profile_sync_config_repo.save(config)
        service = ctx.get_github_sync_service()
        monkeypatch.setattr(service, "_fetch_profiles_recursive", lambda *a, **k: [])
        monkeypatch.setattr(service, "_fetch_instruments", lambda *a, **k: (
            [_instrument("forward"), named("Other", "OtherSeq"), named("Third", "ThirdSeq")], []))
        assert service.sync()[0]
        repo = ctx.instrument_definition_repo
        assert repo.set_enabled_by_name("Other", False)
        restore = _fail_save(monkeypatch, service.instrument_definition_repo,
                             when=lambda inst: inst.name == "Third")
        assert service.sync()[0] is False
        restore()
        assert repo.get_by_name("Other").enabled is False
        assert repo.set_enabled_by_name("Other", True)

        assert service.sync()[0]

        assert repo.get_by_name("Other").enabled is True

    def test_the_noted_switches_go_once_the_instruments_are_written(self, fresh_app):
        """Else an instrument the admin switches back on would be switched
        off again by a later sync while the test profiles are still noted."""
        from seqsetup.utils.clock import utcnow
        _app, ctx, _db = fresh_app
        notes = ctx.profile_sync_config_repo
        notes.mark_writing(utcnow(), "test profiles")
        notes.mark_writing(utcnow(), "instrument settings", {"OtherSeq"})

        assert notes.written(["instrument settings"]) == ["test profiles"]

        assert notes.writing_note()["disabled_instruments"] == []


class TestTheSchedulerTriesAgainSoon:
    """While Mark Ready is paused, the scheduled sync does not wait its whole
    interval (review P2-3)."""

    def _scheduler(self, ctx, minutes_ago):
        from datetime import timedelta
        from seqsetup.services.scheduler import ProfileSyncScheduler
        from seqsetup.utils.clock import utcnow
        config = ctx.profile_sync_config_repo.get()
        config.sync_interval_minutes = 60
        config.last_sync_at = utcnow() - timedelta(minutes=minutes_ago)
        ctx.profile_sync_config_repo.save(config)
        return (ProfileSyncScheduler(ctx.get_github_sync_service(), ctx.profile_sync_config_repo),
                ctx.profile_sync_config_repo.get())

    def test_five_minutes_after_a_sync_that_stopped(self, fresh_app):
        from seqsetup.utils.clock import utcnow
        _app, ctx, _db = fresh_app
        ctx.profile_sync_config_repo.mark_writing(utcnow(), "test profiles")
        scheduler, config = self._scheduler(ctx, 5)
        assert scheduler._should_sync(config) is True
        scheduler, config = self._scheduler(ctx, 4)
        assert scheduler._should_sync(config) is False

    def test_not_when_nothing_is_paused(self, fresh_app):
        _app, ctx, _db = fresh_app
        scheduler, config = self._scheduler(ctx, 5)
        assert scheduler._should_sync(config) is False

    def test_not_when_the_last_sync_finished_but_could_not_lift_it(self, fresh_app):
        """Another sync would not lift it either (instrument sync off, a
        refused file): retrying every 5 minutes would only spend GitHub's
        hourly allowance (second review P3-2)."""
        from seqsetup.utils.clock import utcnow
        _app, ctx, _db = fresh_app
        ctx.profile_sync_config_repo.mark_writing(utcnow(), "instrument settings")
        ctx.profile_sync_config_repo.update_sync_status(
            "error", _still_paused("instrument settings") + " Synced 1 application profiles.", 1)
        scheduler, config = self._scheduler(ctx, 5)
        assert scheduler._should_sync(config) is False
        scheduler, config = self._scheduler(ctx, 60)
        assert scheduler._should_sync(config) is True


class TestTheConfigSyncPageShowsThePause:

    def test_while_paused(self, fresh_app, logged_in_client):
        from seqsetup.utils.clock import utcnow
        _app, ctx, _db = fresh_app
        ctx.profile_sync_config_repo.mark_writing(utcnow(), "test profiles")
        since = ctx.profile_sync_config_repo.writing_since()

        page = html.unescape(logged_in_client.get("/admin/config-sync").text)

        assert (f"Mark Ready is paused: a sync started at {local_time(since)} did not finish "
                "writing the test profiles. Press Sync now to write them again.") in page

    def test_not_otherwise(self, fresh_app, logged_in_client):
        page = html.unescape(logged_in_client.get("/admin/config-sync").text)
        assert "Mark Ready is paused" not in page


class TestSyncsRunOneAtATime:

    def test_a_second_sync_waits_for_the_first(self, fresh_app, monkeypatch):
        """The scheduler's sync and Sync now can overlap; one could clear the
        note while the other is still writing."""
        _app, ctx, _db = fresh_app
        ok, message, _ = _sync(ctx, monkeypatch)
        assert ok, message
        first = _fake_github(ctx, monkeypatch, dict(TEST_FILES), app_files=dict(APP_FILES))
        repo = first.app_profile_repo
        writing, go_on, events = threading.Event(), threading.Event(), []
        original_delete = repo.delete_all

        def slow_delete():
            if not writing.is_set():
                writing.set()
                go_on.wait(10)
            return original_delete()

        monkeypatch.setattr(repo, "delete_all", slow_delete)
        second = github_sync.GitHubSyncService(
            ctx.profile_sync_config_repo, ctx.app_profile_repo, ctx.test_profile_repo)
        monkeypatch.setattr(second, "_fetch_profiles_recursive",
                            lambda *a, **k: events.append("second fetched") or [])

        a = threading.Thread(target=lambda: events.append(("first", first.sync()[0])))
        a.start()
        assert writing.wait(10)
        b = threading.Thread(target=lambda: events.append(("second", second.sync()[0])))
        b.start()
        b.join(1.0)
        assert "second fetched" not in events, events

        go_on.set()
        a.join(10)
        b.join(10)
        assert events[0] == ("first", True), events
        assert events[1] == "second fetched", events

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
import threading

from pymongo.errors import AutoReconnect

from seqsetup.models.sequencing_run import RunStatus
from seqsetup.services import github_sync
from seqsetup.utils.clock import local_time

from .conftest import disable_repos, mark_ready
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
                    "until a sync finishes.")


def _paused(since) -> str:
    return (f"A configuration sync started at {local_time(since)} has not finished writing "
            "the profiles and instrument settings, so they may be incomplete. Mark Ready is "
            "paused until a sync finishes. Try again in a minute; if this stays, an admin "
            "can press Sync now on the Config Sync page.")


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


def _refused_while_paused(client, ctx, run_id):
    resp = mark_ready(client, run_id, ORIGIN)
    since = ctx.profile_sync_config_repo.writing_since()
    assert since is not None
    assert resp.status_code == 409, html.unescape(resp.text)[:300]
    assert _paused(since) in html.unescape(resp.text)
    run = ctx.run_repo.get_by_id(run_id)
    assert run.status == RunStatus.DRAFT
    assert run.generated_samplesheet_v2 is None
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
        _refused_while_paused(logged_in_client, ctx, run.id)

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
        _refused_while_paused(logged_in_client, ctx, run.id)

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
        _refused_while_paused(logged_in_client, ctx, run_id)


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
        assert NEW_ADAPTER in ctx.run_repo.get_by_id(run.id).generated_samplesheet_v2

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

        _refused_while_paused(logged_in_client, ctx, run.id)


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
            ctx.profile_sync_config_repo.mark_writing(utcnow())
            return made

        monkeypatch.setattr(runs, "_pregenerate_exports", exports_then_a_sync_starts)
        _refused_while_paused(logged_in_client, ctx, run.id)


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

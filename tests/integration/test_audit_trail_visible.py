"""Audit events are kept for good and shown on /admin/audit.

No test here raises a logger level or sets the sink by hand: what the page
and the database show is what the app itself records.
"""

import importlib
import json
import logging
import sys

import pytest
from starlette.testclient import TestClient

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)

from .conftest import disable_repos


ORIGIN = {"Origin": "http://testserver"}


def _events(ctx, **kw):
    return ctx.audit_event_repo.search(limit=500, **kw)


def _restart_app():
    """Build the app again against the same test database, the way a process
    restart would: fresh repositories, fresh in-memory log buffer."""
    import seqsetup.startup as startup_module
    from seqsetup.services import log_capture
    for sched in (getattr(startup_module, "_profile_sync_scheduler", None),):
        if sched is not None:
            sched.stop()
    startup_module._db = None
    startup_module._repos = {}
    startup_module._github_sync_service = None
    startup_module._profile_sync_scheduler = None
    startup_module._auth_service = None
    if log_capture._log_capture_handler is not None:
        logging.getLogger("seqsetup").removeHandler(log_capture._log_capture_handler)
        log_capture._log_capture_handler = None
    del sys.modules["seqsetup.app"]
    app_module = importlib.import_module("seqsetup.app")
    sched = getattr(startup_module, "_profile_sync_scheduler", None)
    if sched is not None:
        sched.stop()
    return app_module


class TestAuditEventsAreRecorded:
    """Real actions land in the audit trail and on the page."""

    def test_login_is_recorded(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        (event,) = _events(ctx, event_prefix="login.success")
        assert event.actor == "admin-test"
        page = logged_in_client.get("/admin/audit").text
        assert "login.success" in page and "admin-test" in page

    def test_mark_ready_is_recorded(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = SequencingRun(
            id="audit-visible",
            run_name="AuditVisible",
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
        )
        run.add_sample(Sample(
            sample_id="S1",
            index_pair=IndexPair(
                id="p1", name="p1",
                index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
            ),
        ))
        ctx.run_repo.save(run)
        logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)
        assert ctx.run_repo.get_by_id(run.id).status.value == "ready"

        assert _events(ctx, event_prefix="run.status.changed", target="audit-visible")
        page = logged_in_client.get("/admin/audit", params={"target": "audit-visible"}).text
        assert "run.status.changed" in page

    def test_log_viewer_no_longer_lists_audit_events(self, logged_in_client):
        assert "login.success" not in logged_in_client.get("/admin/logs").text


class TestAuditEventsAreKept:
    """Neither Clear logs nor a restart removes an event."""

    def test_clear_logs_keeps_the_trail(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        assert logged_in_client.post("/admin/logs/clear", headers=ORIGIN).status_code == 200
        assert _events(ctx, event_prefix="login.success")
        assert _events(ctx, event_prefix="logs.cleared")
        assert "login.success" in logged_in_client.get("/admin/audit").text

    def test_restart_keeps_the_trail(self, logged_in_client, fresh_app, admin_user_seeded):
        _app, ctx, _db = fresh_app
        (before,) = _events(ctx, event_prefix="login.success")

        app_module = _restart_app()
        client = TestClient(app_module.app, base_url="http://testserver")
        assert client.post("/login/submit", data=admin_user_seeded, headers=ORIGIN,
                           follow_redirects=False).status_code == 303

        after = app_module._ctx.audit_event_repo.search(limit=10, event_prefix="login.success")
        assert before.id in [e.id for e in after]
        assert len(after) == 2


def _assert_no_secret(db, caplog, *secrets):
    """Neither the stored events nor the logged lines hold any of secrets."""
    raw = json.dumps(list(db["audit_events"].find({}, {"_id": 0})), default=str)
    lines = [r.message for r in caplog.records if r.name == "seqsetup.audit"]
    assert lines
    for secret in secrets:
        assert secret not in raw
        assert not any(secret in line for line in lines)


class TestConfiguredAddressSecretsAreNotKept:
    """N-21: configured web addresses are recorded without password or token,
    however they are written."""

    @pytest.mark.parametrize("url,stored", [
        ("//svc:PASSWORD@lims.invalid/api?api_token=TOKEN", "//lims.invalid/api"),
        ("svc:PASSWORD@lims.invalid/api?api_token=TOKEN", "lims.invalid/api"),
    ])
    def test_blocked_lims_url_is_stored_clean(
        self, fresh_app, logged_in_client, caplog, url, stored
    ):
        from seqsetup.services.sample_api import LimsUrlValidationError, _api_get
        _app, ctx, db = fresh_app
        caplog.set_level(logging.INFO, logger="seqsetup.audit")

        with pytest.raises(LimsUrlValidationError):
            _api_get(url)

        (event,) = _events(ctx, event_prefix="lims.url_blocked")
        assert event.target == stored
        _assert_no_secret(db, caplog, "PASSWORD", "TOKEN")
        page = logged_in_client.get("/admin/audit", params={"event": "lims"}).text
        assert stored in page and "PASSWORD" not in page

    def test_saved_lims_settings_are_stored_clean(self, fresh_app, logged_in_client, caplog):
        """The address the reviewer used: no scheme, no path, a token."""
        _app, ctx, db = fresh_app
        caplog.set_level(logging.INFO, logger="seqsetup.audit")

        r = logged_in_client.post(
            "/admin/settings/sample-api",
            data={"base_url": "lims.example.com?api_token=SECRETTOKEN", "api_key": "KEYVALUE"},
            headers=ORIGIN,
        )
        assert r.status_code == 200, r.text[:300]

        (event,) = _events(ctx, event_prefix="lims_config.updated")
        assert event.details["base_url"] == "lims.example.com"
        _assert_no_secret(db, caplog, "SECRETTOKEN", "KEYVALUE")

    def test_scheduled_sync_target_is_stored_clean(self, fresh_app, caplog):
        from seqsetup.services.scheduler import ProfileSyncScheduler
        _app, ctx, db = fresh_app
        caplog.set_level(logging.INFO, logger="seqsetup.audit")
        config = ctx.profile_sync_config_repo.get()
        config.github_repo_url = "ghp_TOKEN@github.com/org/repo"
        config.sync_enabled = True
        config.last_sync_at = None
        ctx.profile_sync_config_repo.save(config)

        class _Service:
            def sync(self):
                return True, "synced", 0

        ProfileSyncScheduler(_Service(), ctx.profile_sync_config_repo)._check_and_sync()

        events = _events(ctx, event_prefix="config_sync.scheduled")
        assert sorted(e.event for e in events) == [
            "config_sync.scheduled.completed", "config_sync.scheduled.started"]
        assert {e.target for e in events} == {"github.com/org/repo"}
        _assert_no_secret(db, caplog, "ghp_TOKEN")

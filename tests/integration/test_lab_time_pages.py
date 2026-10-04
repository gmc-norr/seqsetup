"""Every page shows times in the display zone (TZ), with the zone's name, and
the API gives times in UTC marked as UTC. Stored times are UTC: 12:00 UTC on
15 January is 13:00 CET in Stockholm, and 09:00 UTC on 1 September 11:00 CEST."""

import logging
from datetime import datetime, timedelta, timezone

import pytest

from seqsetup.models.api_token import ApiToken
from seqsetup.models.audit_event import AuditEvent
from seqsetup.models.deleted_run import DeletedRun
from seqsetup.models.local_user import LocalUser
from seqsetup.models.run_history import RunHistoryEntry
from seqsetup.models.sequencing_run import InstrumentPlatform, RunStatus, SequencingRun
from seqsetup.services.log_capture import get_log_capture_handler
from seqsetup.utils.clock import utcnow

WINTER = datetime(2026, 1, 15, 12, 0)          # shown 2026-01-15 13:00 CET
WINTER_SHOWN = "2026-01-15 13:00 CET"
SUMMER = datetime(2026, 9, 1, 9, 0)            # shown 2026-09-01 11:00 CEST
SUMMER_SHOWN = "2026-09-01 11:00 CEST"
ORIGIN = {"Origin": "http://testserver"}


@pytest.fixture(autouse=True)
def stockholm(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/Stockholm")


def _run(ctx, run_id="lt-run", **kw):
    run = SequencingRun(id=run_id, run_name="LT-RUN", created_by="maker", updated_by="maker",
                        instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        created_at=kw.pop("created_at", WINTER),
                        updated_at=kw.pop("updated_at", WINTER), **kw)
    ctx.run_repo.save(run)
    return run


class TestRunPages:
    def test_the_change_history(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        ctx.run_history_repo.append(RunHistoryEntry(
            run_id="lt-run", timestamp=WINTER, actor="alice", kind="created",
            provenance={"source": "blank", "ref": None}))
        assert WINTER_SHOWN in logged_in_client.get("/runs/lt-run/history").text

    def test_the_run_page_setup_panel(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, updated_at=SUMMER)
        page = logged_in_client.get("/runs/lt-run").text
        assert WINTER_SHOWN in page and SUMMER_SHOWN in page

    def test_the_setup_wizard(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, updated_at=SUMMER)
        page = logged_in_client.get("/runs/new/step/1?run_id=lt-run").text
        assert WINTER_SHOWN in page and SUMMER_SHOWN in page

    def test_the_dashboard(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, updated_at=SUMMER)
        assert SUMMER_SHOWN in logged_in_client.get("/").text


class TestAdminPages:
    def test_api_tokens(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        ctx.api_token_repo.save(ApiToken(
            name="lt-token", token_hash="h", token_prefix="p", created_by="admin-test",
            created_at=WINTER, last_used_at=SUMMER, expires_at=datetime(2027, 1, 15, 12, 0)))
        page = logged_in_client.get("/admin/api-tokens").text
        for shown in (WINTER_SHOWN, SUMMER_SHOWN, "2027-01-15 13:00 CET"):
            assert shown in page, shown
        assert "(EXPIRED)" not in page and "(expires soon)" not in page

    def test_a_token_ending_in_ninety_minutes_is_not_expired(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        ctx.api_token_repo.save(ApiToken(name="lt-soon", token_hash="h", token_prefix="p",
                                         expires_at=utcnow() + timedelta(minutes=90)))
        page = logged_in_client.get("/admin/api-tokens").text
        assert "(expires soon)" in page and "(EXPIRED)" not in page

    def test_a_token_that_ended_an_hour_ago_is_expired(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        ctx.api_token_repo.save(ApiToken(name="lt-gone", token_hash="h", token_prefix="p",
                                         expires_at=utcnow() - timedelta(hours=1)))
        assert "(EXPIRED)" in logged_in_client.get("/admin/api-tokens").text

    def test_users(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        ctx.local_user_repo.save(LocalUser(username="lt.user", display_name="LT", created_at=WINTER))
        row = logged_in_client.get("/admin/users").text.split('id="user-row-lt.user"')[1].split("</tr>")[0]
        assert WINTER_SHOWN in row

    def test_logs(self, logged_in_client):
        record = logging.LogRecord("seqsetup.lt", logging.WARNING, __file__, 1, "lab time probe", None, None)
        record.created = datetime(2026, 1, 15, 12, 0, 5, tzinfo=timezone.utc).timestamp()
        get_log_capture_handler().emit(record)
        page = logged_in_client.get("/admin/logs").text
        row = page.split("lab time probe")[0].rsplit("<tr", 1)[1]
        assert "2026-01-15 13:00:05 CET" in row

    def test_deleted_runs(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = SequencingRun(id="lt-gone", run_name="LT-GONE", status=RunStatus.ARCHIVED,
                            created_at=WINTER, updated_at=WINTER)
        copy = DeletedRun.of(run, "admin-test", SUMMER)
        ctx.deleted_run_repo.start(copy)
        ctx.deleted_run_repo.mark_completed(copy.copy_id, SUMMER)
        assert SUMMER_SHOWN in logged_in_client.get("/admin/deleted-runs").text
        detail = logged_in_client.get(f"/admin/deleted-runs/{copy.copy_id}").text
        assert WINTER_SHOWN in detail and SUMMER_SHOWN in detail


class TestTheAuditTrail:
    def test_times_are_shown_in_the_display_zone(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        ctx.audit_event_repo.append(AuditEvent(
            timestamp=datetime(2026, 1, 15, 12, 0, 5, tzinfo=timezone.utc), event="lt.event"))
        page = logged_in_client.get("/admin/audit", params={"event": "lt.event"}).text
        assert "2026-01-15 13:00:05 CET" in page
        assert "Times are UTC" not in page and "Time (UTC)" not in page
        assert "Times are in the server's time zone" in page

    def test_the_date_search_uses_the_days_of_the_display_zone(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        # 23:30 UTC on 15 January is 00:30 CET on 16 January.
        ctx.audit_event_repo.append(AuditEvent(
            timestamp=datetime(2026, 1, 15, 23, 30, tzinfo=timezone.utc), event="lt.night",
            target="night-event"))
        on_16th = logged_in_client.get("/admin/audit", params={
            "date_from": "2026-01-16", "date_to": "2026-01-16"}).text
        on_15th = logged_in_client.get("/admin/audit", params={
            "date_from": "2026-01-15", "date_to": "2026-01-15"}).text
        assert "night-event" in on_16th and "night-event" not in on_15th

    def test_a_new_token_records_its_end_in_utc_marked_as_utc(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        r = logged_in_client.post("/admin/api-tokens/create",
                                  data={"name": "lt-audit", "expiry_days": "30"}, headers=ORIGIN)
        assert r.status_code == 200
        (event,) = [e for e in ctx.audit_event_repo.search(limit=50, event_prefix="api_token")
                    if e.details.get("expires_at")]
        ends = datetime.fromisoformat(event.details["expires_at"])
        assert ends.utcoffset() == timedelta(0)
        assert abs(ends - (datetime.now(timezone.utc) + timedelta(days=30))) < timedelta(minutes=1)


class TestTheApi:
    def test_run_times_are_utc_marked_as_utc(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, run_id="lt-api", status=RunStatus.READY, updated_at=SUMMER,
             generated_samplesheet_v2="[Header]\n", generated_json="{}")
        plaintext = ApiToken.generate_token()
        token_hash, token_prefix = ApiToken.hash_token(plaintext)
        ctx.api_token_repo.save(ApiToken(name="lt-api", token_hash=token_hash, token_prefix=token_prefix))
        runs = client.get("/api/runs", headers={"Authorization": f"Bearer {plaintext}"}).json()["items"]
        (run,) = [r for r in runs if r["id"] == "lt-api"]
        assert run["created_at"] == "2026-01-15T12:00:00Z"
        assert run["updated_at"] == "2026-09-01T09:00:00Z"

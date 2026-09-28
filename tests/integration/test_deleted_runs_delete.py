"""Deleting a run keeps a copy and its history (spec 2026-09-28 group 2a,
F16 + review P1/P2).

A run that was ever Ready is copied before it is deleted; only the exact
version that was checked is deleted; the copy moves pending -> completed or
abandoned; change history is never deleted."""

from datetime import datetime, timedelta

import pytest
from starlette.testclient import TestClient

from seqsetup.models.local_user import LocalUser
from seqsetup.models.run_history import RunHistoryEntry
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunStatus
from seqsetup.models.user import UserRole

from .conftest import disable_repos

ORIGIN = {"Origin": "http://testserver"}
HX = {**ORIGIN, "HX-Request": "true"}
RUN_CHANGED = "Someone else changed or deleted this run at the same moment"


class TestWiring:
    def test_the_copy_store_is_wired(self, fresh_app):
        from seqsetup.repositories.deleted_run_repo import DeletedRunRepository
        _app, ctx, _db = fresh_app
        assert isinstance(ctx.deleted_run_repo, DeletedRunRepository)


def _make_run(ctx, status=RunStatus.DRAFT, samples=0, was_ready=False, name="Run", sheet=None):
    run = ctx.run_repo.create_run("maker")
    run = ctx.run_repo.get_by_id(run.id)
    run.run_name = name
    for i in range(samples):
        run.add_sample(Sample(sample_id=f"S{i}"))
    if was_ready:
        run.status = RunStatus.READY
    run.status = status
    if sheet is not None:
        run.generated_samplesheet_v2 = sheet
    ctx.run_repo.save(run)
    return run.id


def _history(ctx, run_id):
    ctx.run_history_repo.append(RunHistoryEntry(
        run_id=run_id, timestamp=datetime(2026, 9, 1, 9, 0), actor="maker", kind="updated",
        field_changes=[{"field": "run_name", "before": "Old", "after": "Run"}]))


def _events(ctx, name):
    return [e for e in ctx.audit_event_repo.search(limit=100, event_prefix=name) if e.event == name]


def _copies(db, run_id):
    return list(db["deleted_runs"].find({"run_id": run_id}))


def _bump(ctx, run_id, sample_id="LATE"):
    """Another request changes the run: one more sample, a newer version."""
    other = ctx.run_repo.get_by_id(run_id)
    other.add_sample(Sample(sample_id=sample_id))
    other.updated_at = other.updated_at + timedelta(seconds=1)
    ctx.run_repo.save(other)


def _second_admin(fresh_app):
    app, ctx, _db = fresh_app
    user = LocalUser(username="admin-two", display_name="Admin Two",
                     email="a2@test.local", role=UserRole.ADMIN)
    user.set_password("Cl1nical-Admin-Two!")
    ctx.local_user_repo.save(user)
    client = TestClient(app, base_url="http://testserver")
    r = client.post("/login/submit", data={"username": "admin-two", "password": "Cl1nical-Admin-Two!"},
                    headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    return client


class TestWhoMayDelete:
    """The spec's rules table, both ways."""

    def test_standard_user_cannot_delete_an_empty_draft_that_was_ready(
            self, logged_in_standard_client, fresh_app):
        _app, ctx, db = fresh_app
        run_id = _make_run(ctx, was_ready=True)
        resp = logged_in_standard_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 403
        assert "This run was Ready once, so only an admin can delete it. Nothing was deleted." in resp.text
        assert ctx.run_repo.get_by_id(run_id) is not None
        assert _copies(db, run_id) == []

    def test_admin_deletes_it_and_the_copy_and_history_are_kept(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        run_id = _make_run(ctx, was_ready=True, name="Once ready")
        _history(ctx, run_id)
        resp = logged_in_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run_id) is None
        (copy,) = _copies(db, run_id)
        assert (copy["state"], copy["deleted_by"], copy["run_name"], copy["status"]) == (
            "completed", "admin-test", "Once ready", "draft")
        assert ctx.run_history_repo.list_by_run(run_id, limit=10)
        (event,) = _events(ctx, "run.deleted")
        assert (event.details["kept_copy"], event.details["copy_id"]) == (True, copy["_id"])

    def test_admin_deletes_an_archived_run_and_the_copy_holds_its_sheet(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        run_id = _make_run(ctx, RunStatus.ARCHIVED, samples=2, sheet="[Header]\nSHEET-BYTES\n")
        _history(ctx, run_id)
        assert logged_in_client.delete(f"/runs/{run_id}", headers=HX).status_code == 200
        (copy,) = _copies(db, run_id)
        assert copy["state"] == "completed"
        assert copy["run"]["generated_samplesheet_v2"] == "[Header]\nSHEET-BYTES\n"
        assert [s["sample_id"] for s in copy["run"]["samples"]] == ["S0", "S1"]
        assert ctx.run_history_repo.list_by_run(run_id, limit=10)

    def test_empty_never_ready_draft_goes_without_a_copy_and_keeps_its_history(
            self, logged_in_standard_client, fresh_app):
        _app, ctx, db = fresh_app
        run_id = _make_run(ctx)
        _history(ctx, run_id)
        assert logged_in_standard_client.delete(f"/runs/{run_id}", headers=HX).status_code == 200
        assert ctx.run_repo.get_by_id(run_id) is None
        assert _copies(db, run_id) == []
        assert ctx.run_history_repo.list_by_run(run_id, limit=10)
        (event,) = _events(ctx, "run.deleted")
        assert event.details["kept_copy"] is False


class TestNoDeleteWithoutTheCopy:
    """A run that was ever Ready is never deleted without its copy."""

    def test_a_copy_that_cannot_be_written_stops_the_delete(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, db = fresh_app
        run_id = _make_run(ctx, RunStatus.ARCHIVED, samples=1)
        _history(ctx, run_id)
        monkeypatch.setattr(ctx.deleted_run_repo, "start",
                            lambda copy: (_ for _ in ()).throw(RuntimeError("disk full")))
        resp = logged_in_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 500
        assert "Could not keep a copy of this run, so it was not deleted. Nothing was changed." in resp.text
        assert ctx.run_repo.get_by_id(run_id) is not None
        assert ctx.run_history_repo.list_by_run(run_id, limit=10)
        (event,) = _events(ctx, "run.delete.failed")
        assert (event.outcome, event.details["reason"]) == ("failure", "copy_failed")
        assert _events(ctx, "run.deleted") == []

    def test_no_copy_store_stops_the_delete(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        run_id = _make_run(ctx, RunStatus.ARCHIVED, samples=1)
        disable_repos(ctx, "deleted_run")
        resp = logged_in_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 500
        assert "Could not keep a copy of this run" in resp.text
        assert ctx.run_repo.get_by_id(run_id) is not None
        (event,) = _events(ctx, "run.delete.failed")
        assert event.details["reason"] == "no_copy_store"


class TestReviewCases:
    """The outside review's three reproductions (spec, "Review changes"),
    plus the delete that finished without its copy being marked."""

    def test_run_changed_after_the_copy_is_refused(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, db = fresh_app
        run_id = _make_run(ctx, was_ready=True)
        real_start = ctx.deleted_run_repo.start

        def start_then_someone_adds_a_sample(copy):
            real_start(copy)
            _bump(ctx, run_id)

        monkeypatch.setattr(ctx.deleted_run_repo, "start", start_then_someone_adds_a_sample)
        resp = logged_in_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 409
        assert RUN_CHANGED in resp.text
        assert [s.sample_id for s in ctx.run_repo.get_by_id(run_id).samples] == ["LATE"]
        (copy,) = _copies(db, run_id)
        assert (copy["state"], copy["abandon_reason"]) == ("abandoned", "run_changed")
        (event,) = _events(ctx, "run.delete.failed")
        assert event.details["reason"] == "run_changed"
        assert _events(ctx, "run.deleted") == []
        assert ctx.deleted_run_repo.list_for_page() == []

    def test_run_changed_before_a_delete_without_copy_is_refused(
            self, logged_in_standard_client, fresh_app, monkeypatch):
        _app, ctx, db = fresh_app
        run_id = _make_run(ctx)
        real = ctx.run_repo.delete_if_unchanged

        def someone_adds_a_sample_first(run):
            _bump(ctx, run.id)
            return real(run)

        monkeypatch.setattr(ctx.run_repo, "delete_if_unchanged", someone_adds_a_sample_first)
        resp = logged_in_standard_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 409
        assert RUN_CHANGED in resp.text
        assert [s.sample_id for s in ctx.run_repo.get_by_id(run_id).samples] == ["LATE"]
        assert _copies(db, run_id) == []
        assert _events(ctx, "run.deleted") == []

    @pytest.mark.parametrize("edited_between", [True, False])
    def test_an_older_request_cannot_touch_a_finished_copy(
            self, logged_in_client, fresh_app, monkeypatch, edited_between):
        _app, ctx, db = fresh_app
        run_id = _make_run(ctx, RunStatus.ARCHIVED, samples=1)
        # Request A loads the run ...
        stale = ctx.run_repo.get_by_id(run_id)
        if edited_between:
            # ... a newer version is stored (an archived run cannot be edited
            # in the app; this stands in for any newer stored version) ...
            _bump(ctx, run_id, "NEWER")
        # ... and request B, a second admin, deletes the version it sees.
        b = _second_admin(fresh_app)
        assert b.delete(f"/runs/{run_id}", headers=HX).status_code == 200
        (b_copy,) = _copies(db, run_id)
        assert (b_copy["state"], b_copy["deleted_by"]) == ("completed", "admin-two")

        # Now A goes on with the version it loaded before.
        real_get = ctx.run_repo.get_by_id
        monkeypatch.setattr(ctx.run_repo, "get_by_id",
                            lambda rid: stale if rid == run_id else real_get(rid))
        resp = logged_in_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 409
        assert RUN_CHANGED in resp.text

        copies = {c["_id"]: c for c in _copies(db, run_id)}
        assert copies[b_copy["_id"]] == b_copy                     # untouched, byte for byte
        (a_copy,) = [c for cid, c in copies.items() if cid != b_copy["_id"]]
        assert (a_copy["state"], a_copy["deleted_by"]) == ("abandoned", "admin-test")
        assert [r["copy_id"] for r in ctx.deleted_run_repo.list_for_page()] == [b_copy["_id"]]
        assert len(_events(ctx, "run.deleted")) == 1

    def test_copy_written_but_delete_failed_leaves_the_run_live(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, db = fresh_app
        run_id = _make_run(ctx, RunStatus.ARCHIVED, samples=1)
        monkeypatch.setattr(ctx.run_repo, "delete_if_unchanged",
                            lambda run: (_ for _ in ()).throw(RuntimeError("db down")))
        resp = logged_in_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 500
        assert "Could not delete this run. Reload the page to see whether it is still there." in resp.text
        assert ctx.run_repo.get_by_id(run_id) is not None
        (copy,) = _copies(db, run_id)
        assert copy["state"] == "pending"
        (event,) = _events(ctx, "run.delete.failed")
        assert (event.details["reason"], event.details["copy_id"]) == ("delete_error", copy["_id"])
        assert _events(ctx, "run.deleted") == []

    def test_delete_done_but_copy_not_marked_is_still_a_delete(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, db = fresh_app
        run_id = _make_run(ctx, RunStatus.ARCHIVED, samples=1)
        monkeypatch.setattr(ctx.deleted_run_repo, "mark_completed",
                            lambda copy_id, at: (_ for _ in ()).throw(RuntimeError("db blip")))
        resp = logged_in_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run_id) is None
        (copy,) = _copies(db, run_id)
        assert copy["state"] == "pending"
        (unconfirmed,) = _events(ctx, "run.delete.copy_unconfirmed")
        assert unconfirmed.details["copy_id"] == copy["_id"]
        assert len(_events(ctx, "run.deleted")) == 1


class TestWhatTheCopyHolds:
    """The copy is the run as it is when deleted (second review, P3)."""

    def test_a_draft_sent_back_from_ready_is_copied_without_exports(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        run_id = _make_run(ctx, RunStatus.READY, samples=1, sheet="[Header]\nREADY-SHEET\n")
        # Back to Draft through the real status route: it clears the exports.
        assert logged_in_client.post(f"/runs/{run_id}/status/draft", headers=HX).status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert (run.status, run.was_ready, run.generated_samplesheet_v2) == (RunStatus.DRAFT, True, None)
        sample = run.samples[0].id
        assert logged_in_client.delete(f"/runs/{run_id}/samples/{sample}", headers=HX).status_code == 200
        assert logged_in_client.delete(f"/runs/{run_id}", headers=HX).status_code == 200
        (copy,) = _copies(db, run_id)
        assert copy["state"] == "completed"
        assert copy["run"]["samples"] == []
        assert (copy["run"]["generated_samplesheet_v2"], copy["run"]["generated_json"]) == (None, None)

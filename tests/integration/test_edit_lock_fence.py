"""A change already on its way when the edit lock changes hands is refused
(outside review of 7f858e0, finding 3; the user's choice "Mark run as
changed", 2026-10-14).

The lock is checked once, when the request loads the run; the save then
checks only that the run is the version it loaded. So Take over, Done
editing, and Edit run over a lock someone left now also mark the run
changed: a save loaded before that is refused, like any save that lost a
race. Each test makes the old editor's request hand the lock over between
its guard and its save.
"""

from datetime import timedelta

from seqsetup.routes import samples as samples_module
from seqsetup.utils.clock import utcnow

from .test_edit_lock import ADMIN, OPERATOR, ORIGIN, _draft, _edit, _holder, two  # noqa: F401


def _meanwhile(monkeypatch, action):
    """Run ``action`` inside the settings handler: after the guard loaded
    the run and checked the lock, before ``saving_run``."""
    real = samples_module._parse_mismatches
    seen = {}

    def handed_over_meanwhile(raw):
        if not seen:
            seen["status"] = action()
        return real(raw)

    monkeypatch.setattr(samples_module, "_parse_mismatches", handed_over_meanwhile)
    return seen


def _late_save(admin, ctx, run_id):
    sample = ctx.run_repo.get_by_id(run_id).samples[0]
    return admin.post(f"/runs/{run_id}/samples/{sample.id}/settings",
                      data={"barcode_mismatches_index1": "2"}, headers=ORIGIN)


def _mismatch(ctx, run_id):
    return ctx.run_repo.get_by_id(run_id).samples[0].barcode_mismatches_index1


class TestAChangeOnItsWayIsRefused:

    def test_when_someone_takes_over(self, two, monkeypatch):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        seen = _meanwhile(monkeypatch, lambda: op.post(
            f"/runs/{run_id}/edit-lock/take-over", headers=ORIGIN).status_code)

        resp = _late_save(admin, ctx, run_id)

        assert seen["status"] == 200
        assert _holder(ctx, run_id) == OPERATOR
        assert resp.status_code == 409, resp.text[:300]
        assert _mismatch(ctx, run_id) == 1

    def test_when_the_editor_presses_done_editing(self, two, monkeypatch):
        """Someone else may press Edit run right after and draw the page."""
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        seen = _meanwhile(monkeypatch, lambda: admin.delete(
            f"/runs/{run_id}/edit-lock", headers=ORIGIN).status_code)

        resp = _late_save(admin, ctx, run_id)

        assert seen["status"] == 200
        assert _holder(ctx, run_id) is None
        assert resp.status_code == 409, resp.text[:300]
        assert _mismatch(ctx, run_id) == 1

    def test_when_someone_presses_edit_run_over_a_lock_left_behind(self, two, monkeypatch):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)

        def left_then_taken():
            ctx.edit_lock_repo.collection.update_one(
                {"_id": run_id}, {"$set": {"seen_at": utcnow() - timedelta(minutes=4)}})
            return op.post(f"/runs/{run_id}/edit-lock", headers=ORIGIN).status_code

        seen = _meanwhile(monkeypatch, left_then_taken)

        resp = _late_save(admin, ctx, run_id)

        assert seen["status"] == 200
        assert _holder(ctx, run_id) == OPERATOR
        assert resp.status_code == 409, resp.text[:300]
        assert _mismatch(ctx, run_id) == 1


class TestTheRunShowsTheHandOver:

    def test_take_over_marks_the_run_changed_by_the_new_editor(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        before = ctx.run_repo.get_by_id(run_id)

        op.post(f"/runs/{run_id}/edit-lock/take-over", headers=ORIGIN)

        after = ctx.run_repo.get_by_id(run_id)
        assert after.updated_at > before.updated_at
        assert after.updated_by == OPERATOR
        assert after.to_dict()["samples"] == before.to_dict()["samples"]

    def test_done_editing_marks_the_run_changed(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        before = ctx.run_repo.get_by_id(run_id)

        admin.delete(f"/runs/{run_id}/edit-lock", headers=ORIGIN)

        after = ctx.run_repo.get_by_id(run_id)
        assert after.updated_at > before.updated_at
        assert after.updated_by == ADMIN


class TestNothingIsMarkedWhenNoOneElseHeldIt:
    """Edit run on a run nobody holds, or pressing it again, hands nothing
    over: the run's Updated time stays."""

    def test_edit_run_on_a_free_run(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        before = ctx.run_repo.get_by_id(run_id).updated_at

        _edit(admin, run_id)

        assert ctx.run_repo.get_by_id(run_id).updated_at == before

    def test_edit_run_again(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        before = ctx.run_repo.get_by_id(run_id).updated_at

        _edit(admin, run_id)

        assert ctx.run_repo.get_by_id(run_id).updated_at == before

    def test_done_editing_by_someone_who_is_not_editing(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        before = ctx.run_repo.get_by_id(run_id).updated_at

        op.delete(f"/runs/{run_id}/edit-lock", headers=ORIGIN)

        assert _holder(ctx, run_id) == ADMIN
        assert ctx.run_repo.get_by_id(run_id).updated_at == before

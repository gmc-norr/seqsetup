"""A change already on its way when someone else starts editing is refused
(outside review of 7f858e0, finding 3; the user's choice "Mark run as
changed", 2026-10-14).

The lock is checked once, when the request loads the run; the save then
checks only that the run is the version it loaded. So whoever starts
editing a run they did not hold -- Edit run, or Take over -- also marks the
run changed, after writing the lock: a save loaded before that is refused,
like any save that lost a race. Done editing marks nothing, so the editor's
own last change, still on its way, is kept (review of 999447b, P2). Each
test makes the old editor's request hand the lock over between its guard
and its save.
"""

from datetime import timedelta

from seqsetup.models.sequencing_run import RunStatus
from seqsetup.routes import samples as samples_module
from seqsetup.utils.clock import utcnow

from .page_shows import shown_setting
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
    # target_setting: what the box showed, as the row sends it (design note
    # 2026-10-17, step 4).
    shown = shown_setting(admin, run_id, sample.id, "barcode_mismatches_index1")
    return admin.post(f"/runs/{run_id}/samples/{sample.id}/settings",
                      data={"barcode_mismatches_index1": "2",
                            "target_setting": shown}, headers=ORIGIN)


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

    def test_when_someone_presses_edit_run_after_done_editing(self, two, monkeypatch):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)

        def done_then_someone_edits():
            admin.delete(f"/runs/{run_id}/edit-lock", headers=ORIGIN)
            return op.post(f"/runs/{run_id}/edit-lock", headers=ORIGIN).status_code

        seen = _meanwhile(monkeypatch, done_then_someone_edits)

        resp = _late_save(admin, ctx, run_id)

        assert seen["status"] == 200
        assert _holder(ctx, run_id) == OPERATOR
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


class TestTheEditorsOwnLastChangeIsKept:

    def test_when_they_press_done_editing_while_it_is_on_its_way(self, two, monkeypatch):
        """Done editing reloads the page, so a refusal would go unseen."""
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        seen = _meanwhile(monkeypatch, lambda: admin.delete(
            f"/runs/{run_id}/edit-lock", headers=ORIGIN).status_code)

        resp = _late_save(admin, ctx, run_id)

        assert seen["status"] == 200
        assert _holder(ctx, run_id) is None
        assert resp.status_code == 200, resp.text[:300]
        assert _mismatch(ctx, run_id) == 2


class TestTheRunShowsWhoStartedEditing:

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

    def test_edit_run_on_a_free_run_marks_it_changed_by_the_editor(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        before = ctx.run_repo.get_by_id(run_id).updated_at

        _edit(op, run_id)

        after = ctx.run_repo.get_by_id(run_id)
        assert after.updated_at > before
        assert after.updated_by == OPERATOR

    def test_take_over_on_a_free_run_marks_it_changed_by_the_editor(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        before = ctx.run_repo.get_by_id(run_id).updated_at

        op.post(f"/runs/{run_id}/edit-lock/take-over", headers=ORIGIN)

        after = ctx.run_repo.get_by_id(run_id)
        assert _holder(ctx, run_id) == OPERATOR
        assert after.updated_at > before
        assert after.updated_by == OPERATOR


class TestTheGuardLoadsTheRunBeforeCheckingTheLock:
    """Checking the lock first and loading after would let a take-over in
    between hand the request the marked version, and its save would land
    (review of 6b123a2, P3-4)."""

    def test_a_take_over_just_before_the_load_is_refused(self, two, monkeypatch):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        sample = ctx.run_repo.get_by_id(run_id).samples[0]
        real = ctx.run_repo.get_by_id
        seen = {}

        def taken_over_first(*a, **k):
            if not seen:
                seen["status"] = None
                seen["status"] = op.post(f"/runs/{run_id}/edit-lock/take-over",
                                         headers=ORIGIN).status_code
            return real(*a, **k)

        # Read before the monkeypatch: loading the page would spend the
        # one take-over this test arms.
        shown = shown_setting(admin, run_id, sample.id, "barcode_mismatches_index1")
        monkeypatch.setattr(ctx.run_repo, "get_by_id", taken_over_first)
        resp = admin.post(f"/runs/{run_id}/samples/{sample.id}/settings",
                          data={"barcode_mismatches_index1": "2",
                                "target_setting": shown}, headers=ORIGIN)
        monkeypatch.undo()

        assert seen["status"] == 200
        assert _holder(ctx, run_id) == OPERATOR
        assert resp.status_code == 409, resp.text[:300]
        assert _mismatch(ctx, run_id) == 1


class TestNothingIsMarkedWhenTheEditorStaysTheSame:

    def test_edit_run_again(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        before = ctx.run_repo.get_by_id(run_id).updated_at

        _edit(admin, run_id)

        assert ctx.run_repo.get_by_id(run_id).updated_at == before

    def test_edit_run_on_your_own_lock_left_behind(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        ctx.edit_lock_repo.collection.update_one(
            {"_id": run_id}, {"$set": {"seen_at": utcnow() - timedelta(minutes=4)}})
        before = ctx.run_repo.get_by_id(run_id).updated_at

        _edit(admin, run_id)

        assert ctx.run_repo.get_by_id(run_id).updated_at == before

    def test_take_over_of_your_own_lock(self, two):
        """From a second tab, say: the editor's change from the first one is kept."""
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        before = ctx.run_repo.get_by_id(run_id).updated_at

        resp = admin.post(f"/runs/{run_id}/edit-lock/take-over", headers=ORIGIN)

        assert resp.status_code == 200
        assert _holder(ctx, run_id) == ADMIN
        assert ctx.run_repo.get_by_id(run_id).updated_at == before

    def test_done_editing(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        before = ctx.run_repo.get_by_id(run_id).updated_at

        admin.delete(f"/runs/{run_id}/edit-lock", headers=ORIGIN)

        assert _holder(ctx, run_id) is None
        assert ctx.run_repo.get_by_id(run_id).updated_at == before


class TestTheLockIsWrittenBeforeTheRunIsMarked:
    """A request that loads the run after the mark must find the new lock
    (review of 999447b, P3-3)."""

    def _order(self, ctx, monkeypatch):
        order = []
        for name in ("take", "replace"):
            real = getattr(ctx.edit_lock_repo, name)
            monkeypatch.setattr(ctx.edit_lock_repo, name,
                                lambda *a, _real=real, _name=name, **k: order.append(_name) or _real(*a, **k))
        real_mark = ctx.run_repo.mark_changed
        monkeypatch.setattr(ctx.run_repo, "mark_changed",
                            lambda *a, **k: order.append("mark") or real_mark(*a, **k))
        return order

    def test_edit_run(self, two, monkeypatch):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        order = self._order(ctx, monkeypatch)

        _edit(op, run_id)

        assert order == ["take", "mark"], order

    def test_take_over(self, two, monkeypatch):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)
        order = self._order(ctx, monkeypatch)

        op.post(f"/runs/{run_id}/edit-lock/take-over", headers=ORIGIN)

        assert order == ["replace", "mark"], order


class TestOnlyADraftIsMarked:

    def test_a_ready_run_keeps_its_version(self, two):
        """A Take over racing the old editor's Mark Ready must not move a
        Ready run's Updated time (review of 999447b, P3-2)."""
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.READY
        ctx.run_repo.save(run)
        before = ctx.run_repo.get_by_id(run_id)

        assert ctx.run_repo.mark_changed(run_id, utcnow(), OPERATOR) is False

        after = ctx.run_repo.get_by_id(run_id)
        assert (after.updated_at, after.updated_by) == (before.updated_at, before.updated_by)

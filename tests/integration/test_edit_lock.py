"""One person edits a Draft run at a time (the user's decision, 2026-10-13).

Two people adding samples, indexes and lanes to one run at once is
confusing, so a Draft has one editor. Edit run takes the lock, Done editing
gives it back, and anyone may take it over after a confirmation. Every
change to a Draft is refused unless the person sending it holds the lock.
"""

from datetime import timedelta

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunCycles, RunStatus, SequencingRun
from seqsetup.utils.clock import utcnow

from .conftest import mark_ready

ORIGIN = {"Origin": "http://testserver"}
ADMIN, OPERATOR = "admin-test", "operator"


def _draft(ctx, run_id="lock-run", samples=0):
    run = SequencingRun(id=run_id, run_name="Lock run", flowcell_type="10B",
                        run_cycles=RunCycles(151, 151, 10, 10))
    for n in range(samples):
        run.add_sample(Sample(sample_id=f"S{n + 1}"))
    ctx.run_repo.save(run)
    return run.id


def _rename(client, run_id, name="Renamed"):
    return client.post(f"/runs/{run_id}/name", data={"run_name": name}, headers=ORIGIN)


def _edit(client, run_id):
    return client.post(f"/runs/{run_id}/edit-lock", headers=ORIGIN)


def _holder(ctx, run_id):
    lock = ctx.edit_lock_repo.get(run_id)
    return lock.username if lock else None


def _events(ctx, prefix):
    return [(e.event, e.actor, e.details) for e in ctx.audit_event_repo.search(limit=50, event_prefix=prefix)]


@pytest.fixture
def two(fresh_app, logged_in_client, logged_in_standard_client):
    _app, ctx, _db = fresh_app
    return ctx, logged_in_client, logged_in_standard_client


class TestEditRun:
    def test_it_takes_a_free_run_and_then_saves_go_through(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)

        resp = _edit(admin, run_id)

        assert resp.status_code == 200 and resp.headers["HX-Redirect"] == f"/runs/{run_id}"
        assert _holder(ctx, run_id) == ADMIN
        assert _rename(admin, run_id).status_code == 200
        assert ctx.run_repo.get_by_id(run_id).run_name == "Renamed"
        assert [(e, a) for e, a, _d in _events(ctx, "run.edit.")] == [("run.edit.started", ADMIN)]

    def test_it_is_refused_while_someone_else_edits_and_names_them(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)

        resp = _edit(op, run_id)

        assert resp.status_code == 409
        assert "Test Admin is editing this run" in resp.text
        assert _holder(ctx, run_id) == ADMIN

    def test_someone_elses_lock_not_seen_for_three_minutes_is_free(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)
        ctx.edit_lock_repo.collection.update_one(
            {"_id": run_id}, {"$set": {"seen_at": utcnow() - timedelta(minutes=4)}})

        assert _edit(op, run_id).status_code == 200
        assert _holder(ctx, run_id) == OPERATOR

    def test_a_run_that_is_not_a_draft_has_no_editing(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.READY
        ctx.run_repo.save(run)

        assert _edit(admin, run_id).status_code == 403
        assert _holder(ctx, run_id) is None


class TestEveryChangeNeedsTheLock:
    def test_a_save_with_nobody_editing_is_refused(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)

        resp = _rename(admin, run_id)

        assert resp.status_code == 409
        assert "You are not editing this run, so nothing was saved" in resp.text
        assert ctx.run_repo.get_by_id(run_id).run_name == "Lock run"

    def test_a_save_while_someone_else_edits_is_refused_and_names_them(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)

        resp = _rename(op, run_id)

        assert resp.status_code == 409
        assert "Test Admin has been editing this run since" in resp.text
        assert ctx.run_repo.get_by_id(run_id).run_name == "Lock run"

    def test_the_holders_old_lock_still_saves_when_nobody_took_it(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)
        ctx.edit_lock_repo.collection.update_one(
            {"_id": run_id}, {"$set": {"seen_at": utcnow() - timedelta(minutes=30)}})

        assert _rename(admin, run_id).status_code == 200
        assert ctx.edit_lock_repo.get(run_id).seen_at > utcnow() - timedelta(minutes=1)

    def test_a_sample_change_is_refused_too(self, two):
        ctx, _admin, op = two
        run_id = _draft(ctx, samples=1)
        sample_id = ctx.run_repo.get_by_id(run_id).samples[0].id

        resp = op.delete(f"/runs/{run_id}/samples/{sample_id}", headers=ORIGIN)

        assert resp.status_code == 409
        assert len(ctx.run_repo.get_by_id(run_id).samples) == 1


class TestTakeOver:
    def test_anyone_may_take_over_and_the_old_holder_is_then_refused(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)

        resp = op.post(f"/runs/{run_id}/edit-lock/take-over", headers=ORIGIN)

        assert resp.status_code == 200 and resp.headers["HX-Redirect"] == f"/runs/{run_id}"
        assert _holder(ctx, run_id) == OPERATOR
        refused = _rename(admin, run_id)
        assert refused.status_code == 409 and "Test Operator has been editing this run since" in refused.text
        assert _rename(op, run_id).status_code == 200
        (taken,) = [d for e, a, d in _events(ctx, "run.edit.taken_over") if a == OPERATOR]
        assert taken["from_user"] == ADMIN

    def test_taking_over_a_free_run_names_nobody(self, two):
        ctx, _admin, op = two
        run_id = _draft(ctx)

        assert op.post(f"/runs/{run_id}/edit-lock/take-over", headers=ORIGIN).status_code == 200
        (taken,) = [d for _e, _a, d in _events(ctx, "run.edit.taken_over")]
        assert taken["from_user"] == ""


class TestDoneEditing:
    def test_it_frees_the_run_and_later_saves_are_refused(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)

        resp = admin.delete(f"/runs/{run_id}/edit-lock", headers=ORIGIN)

        assert resp.status_code == 200 and resp.headers["HX-Redirect"] == f"/runs/{run_id}"
        assert _holder(ctx, run_id) is None
        assert _rename(admin, run_id).status_code == 409
        assert ("run.edit.ended", ADMIN) in [(e, a) for e, a, _d in _events(ctx, "run.edit.")]

    def test_it_never_frees_someone_elses_lock(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)

        op.delete(f"/runs/{run_id}/edit-lock", headers=ORIGIN)

        assert _holder(ctx, run_id) == ADMIN


class TestTheHeartbeat:
    def test_it_keeps_the_holder_seen(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)
        ctx.edit_lock_repo.collection.update_one(
            {"_id": run_id}, {"$set": {"seen_at": utcnow() - timedelta(minutes=2)}})

        resp = admin.post(f"/runs/{run_id}/edit-lock/heartbeat", headers=ORIGIN)

        assert resp.json() == {"editing": True}
        assert ctx.edit_lock_repo.get(run_id).seen_at > utcnow() - timedelta(minutes=1)

    def test_it_tells_a_page_whose_lock_was_taken(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)
        op.post(f"/runs/{run_id}/edit-lock/take-over", headers=ORIGIN)

        answer = admin.post(f"/runs/{run_id}/edit-lock/heartbeat", headers=ORIGIN).json()

        assert answer["editing"] is False
        assert "Test Operator is editing this run now (since" in answer["message"]

    def test_heartbeats_are_not_audited(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)
        admin.post(f"/runs/{run_id}/edit-lock/heartbeat", headers=ORIGIN)
        assert [e for e, _a, _d in _events(ctx, "run.edit.")] == ["run.edit.started"]


class TestTheLockFollowsTheRun:
    def test_a_new_run_is_its_makers(self, two):
        ctx, admin, op = two
        resp = admin.post("/runs/new", headers=ORIGIN, follow_redirects=False)
        run_id = resp.headers["location"].split("run_id=", 1)[1]

        assert _holder(ctx, run_id) == ADMIN
        assert _rename(op, run_id).status_code == 409

    def test_a_copy_is_its_makers(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)

        resp = op.post(f"/runs/{run_id}/duplicate", headers=ORIGIN, follow_redirects=False)

        copy_id = resp.headers["location"].rsplit("/", 1)[1]
        assert copy_id != run_id and _holder(ctx, copy_id) == OPERATOR

    def test_mark_ready_needs_the_lock_and_frees_it(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)

        refused = op.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)
        assert refused.status_code == 409
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT

    def test_the_holder_marks_it_ready_and_the_lock_goes(self, two):
        from .conftest import disable_repos
        from .test_group_1c import _clean_run
        ctx, admin, _op = two
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _clean_run(ctx, "lock-ready").id
        _edit(admin, run_id)

        assert mark_ready(admin, run_id, ORIGIN).status_code == 200
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.READY
        assert _holder(ctx, run_id) is None

    def test_back_to_draft_gives_the_lock_to_whoever_pressed_it(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.READY
        ctx.run_repo.save(run)

        resp = op.post(f"/runs/{run_id}/status/draft", headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert _holder(ctx, run_id) == OPERATOR

    def test_deleting_an_empty_draft_is_refused_while_someone_else_edits(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)

        assert op.delete(f"/runs/{run_id}", headers=ORIGIN).status_code == 409
        assert ctx.run_repo.get_by_id(run_id) is not None

    def test_deleting_it_takes_the_lock_away_too(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)

        assert admin.delete(f"/runs/{run_id}", headers=ORIGIN).status_code == 200
        assert ctx.run_repo.get_by_id(run_id) is None and _holder(ctx, run_id) is None


def _page(client, run_id):
    return client.get(f"/runs/{run_id}").text


MARK_READY = '/status/ready"'
EDIT_SETUP = "Edit setup</a>"
SET_TEST = 'class="validate-fix"'


def _a_test_profile(ctx):
    """The Check panel offers "Set test" only when there is a test to set."""
    from seqsetup.models.test_profile import TestProfile
    ctx.test_profile_repo.save(TestProfile(test_type="WGS"))
HEARTBEAT = "editLock("


class TestWhatTheRunPageShows:
    """Only the editor sees the edit controls; everyone else sees the run
    read-only, with who is editing and the button to get the lock."""

    def test_the_editor_sees_the_edit_page_and_done_editing(self, two):
        ctx, admin, _op = two
        _a_test_profile(ctx)
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)

        page = _page(admin, run_id)

        assert "You are editing this run" in page and "Done editing" in page
        assert MARK_READY in page and EDIT_SETUP in page and SET_TEST in page
        assert f'{HEARTBEAT}"/runs/{run_id}/edit-lock/heartbeat"' in page
        assert "locked-message" not in page

    def test_someone_else_sees_who_is_editing_and_take_over(self, two):
        ctx, admin, op = two
        _a_test_profile(ctx)
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)

        page = _page(op, run_id)

        assert "Test Admin is editing this run" in page and "Take over editing" in page
        assert "If you take over, Test Admin can no longer save" in page
        assert MARK_READY not in page and EDIT_SETUP not in page and SET_TEST not in page
        assert HEARTBEAT not in page
        assert "Press Edit run to make changes." in page

    def test_nobody_editing_offers_edit_run(self, two):
        ctx, _admin, op = two
        run_id = _draft(ctx, samples=1)

        page = _page(op, run_id)

        assert ">Edit run</button>" in page and "Take over editing" not in page
        assert MARK_READY not in page and EDIT_SETUP not in page and HEARTBEAT not in page

    def test_someone_elses_old_lock_shows_as_free(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)
        ctx.edit_lock_repo.collection.update_one(
            {"_id": run_id}, {"$set": {"seen_at": utcnow() - timedelta(minutes=4)}})

        page = _page(op, run_id)

        assert ">Edit run</button>" in page and "Take over editing" not in page

    def test_a_ready_run_has_no_editing_buttons(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.READY
        ctx.run_repo.save(run)

        page = _page(admin, run_id)

        assert "Edit run</button>" not in page and "Done editing" not in page
        assert "Return to Draft" in page

    def test_the_check_panel_offers_its_fixes_to_the_editor_only(self, two):
        ctx, admin, op = two
        _a_test_profile(ctx)
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)

        assert SET_TEST in admin.get(f"/runs/{run_id}/validate-panel").text
        assert SET_TEST not in op.get(f"/runs/{run_id}/validate-panel").text

    def test_back_to_draft_answers_with_the_edit_page_parts(self, two):
        ctx, _admin, op = two
        run_id = _draft(ctx, samples=1)
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.READY
        ctx.run_repo.save(run)

        answer = op.post(f"/runs/{run_id}/status/draft", headers=ORIGIN).text

        assert "You are editing this run" in answer and MARK_READY in answer
        assert "locked-message" not in answer


class TestTheSetupPage:
    def test_the_editor_gets_it(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)

        resp = admin.get(f"/runs/new/step/1?run_id={run_id}", follow_redirects=False)

        assert resp.status_code == 200
        assert f'{HEARTBEAT}"/runs/{run_id}/edit-lock/heartbeat"' in resp.text

    def test_anyone_else_is_sent_to_the_run_page(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)

        resp = op.get(f"/runs/new/step/1?run_id={run_id}", follow_redirects=False)

        assert resp.status_code == 303 and resp.headers["location"] == f"/runs/{run_id}"


class TestTheHeartbeatsMessage:
    def test_it_says_who_has_it_now(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)
        op.post(f"/runs/{run_id}/edit-lock/take-over", headers=ORIGIN)

        message = admin.post(f"/runs/{run_id}/edit-lock/heartbeat", headers=ORIGIN).json()["message"]

        assert message.startswith("Test Operator is editing this run now (since ")
        assert message.endswith("). Reload the page: your changes are no longer saved.")

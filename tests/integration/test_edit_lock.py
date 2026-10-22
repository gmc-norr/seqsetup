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

from .conftest import mark_ready, seed_profiles

ORIGIN = {"Origin": "http://testserver"}
ADMIN, OPERATOR = "admin-test", "operator"


def _draft(ctx, run_id="lock-run", samples=0):
    run = SequencingRun(id=run_id, run_name="Lock run", flowcell_type="10B",
                        run_cycles=RunCycles(151, 151, 10, 10))
    for n in range(samples):
        run.add_sample(Sample(lanes=[1], sample_id=f"S{n + 1}"))
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
        from .test_group_1c import _clean_run
        ctx, admin, _op = two
        seed_profiles(ctx, lane=False)
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
    ctx.test_profile_repo.save(TestProfile(test_type="WGS", test_name="WGS"))
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
        assert "Test Admin is editing this run. Only they can change it now." in page

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


class TestStartingFromATemplate:
    """"Start from a template" deletes the blank run the New Run page made,
    but not while someone else is editing it; the new run is its maker's."""

    def _template(self, client, ctx):
        from .test_new_run_from_template_choice import _make_template
        return _make_template(client, ctx, "Lock tmpl")

    def test_the_blank_run_is_kept_while_someone_else_edits_it(self, two):
        from .test_new_run_from_template_choice import _choose, _new_blank_run
        ctx, admin, op = two
        template_id = self._template(admin, ctx)
        blank = _new_blank_run(admin)
        op.post(f"/runs/{blank}/edit-lock/take-over", headers=ORIGIN)

        resp = _choose(admin, template_id, blank)

        assert resp.status_code == 303
        assert ctx.run_repo.get_by_id(blank) is not None and _holder(ctx, blank) == OPERATOR
        new_id = resp.headers["location"].rsplit("/", 1)[1]
        assert _holder(ctx, new_id) == ADMIN

    def test_your_own_blank_run_goes_with_its_lock(self, two):
        from .test_new_run_from_template_choice import _choose, _new_blank_run
        ctx, admin, _op = two
        template_id = self._template(admin, ctx)
        blank = _new_blank_run(admin)

        assert _choose(admin, template_id, blank).status_code == 303
        assert ctx.run_repo.get_by_id(blank) is None and _holder(ctx, blank) is None


class TestTheHeartbeatIsNotActivity:
    """Review P1 (2026-10-13): the heartbeat kept the login alive, so an
    edit page left open switched off the idle logout. It must not count as
    use; an ended login stops it."""

    def _seen(self, ctx, username):
        return ctx.web_session_repo.collection.find_one({"username": username})["last_seen_at"]

    def test_a_heartbeat_does_not_move_the_logins_last_use(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)
        earlier = utcnow() - timedelta(minutes=20)
        ctx.web_session_repo.collection.update_many({"username": ADMIN}, {"$set": {"last_seen_at": earlier}})

        assert admin.post(f"/runs/{run_id}/edit-lock/heartbeat", headers=ORIGIN).json() == {"editing": True}

        assert abs(self._seen(ctx, ADMIN) - earlier) < timedelta(seconds=1)
        admin.get(f"/runs/{run_id}")
        assert self._seen(ctx, ADMIN) > utcnow() - timedelta(minutes=1)

    def test_an_idle_login_still_ends_with_the_page_open(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)
        ctx.web_session_repo.collection.update_many(
            {"username": ADMIN}, {"$set": {"last_seen_at": utcnow() - timedelta(minutes=31)}})

        resp = admin.post(f"/runs/{run_id}/edit-lock/heartbeat", headers=ORIGIN, follow_redirects=False)

        assert resp.status_code == 303 and resp.headers["location"] == "/login"

    def test_a_run_that_left_draft_answers_403(self, two):
        ctx, admin, _op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.READY
        ctx.run_repo.save(run)

        assert admin.post(f"/runs/{run_id}/edit-lock/heartbeat", headers=ORIGIN).status_code == 403


class TestMarkReadyChecksTheLockAgainBeforeSaving:
    """Review P3-2: Mark Ready writes its exports for seconds; someone who
    takes over meanwhile keeps the lock, and the run stays a Draft."""

    def test_a_take_over_during_the_exports_is_refused(self, two, monkeypatch):
        from seqsetup.routes import runs as runs_module
        from .test_group_1c import _clean_run
        ctx, admin, op = two
        seed_profiles(ctx, lane=False)
        run_id = _clean_run(ctx, "lock-lost").id
        _edit(admin, run_id)
        generate = runs_module._pregenerate_exports

        def taken_meanwhile(run, ctx_, **kw):
            op.post(f"/runs/{run_id}/edit-lock/take-over", headers=ORIGIN)
            return generate(run, ctx_, **kw)

        monkeypatch.setattr(runs_module, "_pregenerate_exports", taken_meanwhile)

        resp = mark_ready(admin, run_id, ORIGIN)

        assert resp.status_code == 409 and "Test Operator has been editing this run since" in resp.text
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT
        assert _holder(ctx, run_id) == OPERATOR
        reasons = [d.get("reason") for e, _a, d in _events(ctx, "run.status.denied")]
        assert reasons == ["edit_lock_lost"], reasons


class TestMoreLockPaths:
    def test_deleting_a_draft_whose_other_lock_is_old_is_allowed(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)
        ctx.edit_lock_repo.collection.update_one(
            {"_id": run_id}, {"$set": {"seen_at": utcnow() - timedelta(minutes=4)}})

        assert op.delete(f"/runs/{run_id}", headers=ORIGIN).status_code == 200
        assert ctx.run_repo.get_by_id(run_id) is None and _holder(ctx, run_id) is None

    def test_a_run_from_the_templates_page_is_its_makers(self, two):
        from .test_new_run_from_template_choice import _make_template
        ctx, admin, op = two
        template_id = _make_template(admin, ctx, "Lock tmpl page")

        resp = op.post(f"/runs/new/from-template/{template_id}", headers=ORIGIN, follow_redirects=False)

        assert resp.status_code == 303
        assert _holder(ctx, resp.headers["location"].rsplit("/", 1)[1]) == OPERATOR

    def test_taking_an_old_lock_names_whose_it_was(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)
        ctx.edit_lock_repo.collection.update_one(
            {"_id": run_id}, {"$set": {"seen_at": utcnow() - timedelta(minutes=4)}})

        _edit(op, run_id)

        (started,) = [d for e, a, d in _events(ctx, "run.edit.started") if a == OPERATOR]
        assert started["from_user"] == ADMIN

    def test_a_refused_edit_run_says_to_reload_for_take_over(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx)
        _edit(admin, run_id)

        assert "reload the page and press Take over editing" in _edit(op, run_id).text

    def test_the_read_only_page_names_who_is_editing(self, two):
        ctx, admin, op = two
        run_id = _draft(ctx, samples=1)
        _edit(admin, run_id)

        assert "Test Admin is editing this run. Only they can change it now." in _page(op, run_id)


class TestEveryRunChangeIsGuarded:
    """Every POST, PUT, PATCH or DELETE under /runs/{run_id} loads its run
    with get_editable_run, or is on this list with the reason it need not."""

    NOT_EDITABLE_GUARDED = {
        ("POST", "/runs/{run_id}/status/{status}"): "checks the lock itself for Mark Ready",
        ("POST", "/runs/{run_id}/archive"): "Ready runs only",
        ("DELETE", "/runs/{run_id}"): "checks someone else's live lock itself",
        ("POST", "/runs/{run_id}/duplicate"): "reads the run, makes a new one",
        ("POST", "/runs/{run_id}/save-as-template"): "reads the run, writes a template",
        ("POST", "/runs/{run_id}/edit-lock"): "the lock itself",
        ("DELETE", "/runs/{run_id}/edit-lock"): "the lock itself",
        ("POST", "/runs/{run_id}/edit-lock/take-over"): "the lock itself",
        ("POST", "/runs/{run_id}/edit-lock/heartbeat"): "the lock itself",
    }

    def _uses(self, dependant, fn):
        return any(d.call is fn or self._uses(d, fn) for d in dependant.dependencies)

    def _api_routes(self, routes):
        """Every APIRoute, also inside included routers (FastAPI keeps an
        included router whole, as its original_router)."""
        from fastapi.routing import APIRoute
        for route in routes:
            if isinstance(route, APIRoute):
                yield route
            elif hasattr(route, "original_router"):
                yield from self._api_routes(route.original_router.routes)

    def test_each_one_is_guarded_or_listed(self, fresh_app):
        from seqsetup.routes.dependencies import get_editable_run
        app, _ctx, _db = fresh_app
        found = set()
        unguarded = []
        for route in self._api_routes(app.routes):
            if not route.path.startswith("/runs/{run_id}"):
                continue
            for method in route.methods & {"POST", "PUT", "PATCH", "DELETE"}:
                found.add((method, route.path))
                if not self._uses(route.dependant, get_editable_run) and (
                        method, route.path) not in self.NOT_EDITABLE_GUARDED:
                    unguarded.append((method, route.path))
        assert len(found) > 20, found
        assert unguarded == []
        assert set(self.NOT_EDITABLE_GUARDED) <= found, set(self.NOT_EDITABLE_GUARDED) - found

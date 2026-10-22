"""No page action stops the app for everyone else (project review F9; the
user's word, 2026-10-22).

The app runs one process with one event loop. A route written ``async def``
runs on that loop, so every blocking thing it does -- a MongoDB save, the
history record, rendering the answer -- made every other request wait: about
80 ms per sample edit, and up to the database's 30-second socket timeout when
the database was slow. Every route is a plain ``def`` now, which Starlette
runs on a worker thread; only reading the request's form stays on the loop.

That loop had also lined up one person's quick saves to one run by accident:
two row boxes saved a split second apart, or a row save and a bulk Apply. On
worker threads they would overlap, and the second would lose the run's
version check -- "modified by another user", for the person's own edit. So
every request that edits a run waits its turn for that run
(``services/run_turns.py``, taken by ``get_editable_run`` before it loads the
run). Requests for different runs do not wait for each other, and a turn that
does not come is refused, never waited for without end.
"""

import inspect
import threading

import pytest
from fastapi.routing import APIRoute
from starlette.routing import Mount

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun

from .conftest import hold_edit_lock
from .test_group_a1 import ORIGIN, RUN, _run, _stored

OTHER = "f9-other-run"


@pytest.fixture
def two_rows(fresh_app):
    _app, ctx, _db = fresh_app
    _run(ctx, ["PAT1", "PAT2"])
    return ctx


def _other_run(ctx):
    run = SequencingRun(id=OTHER, run_name="Other", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10))
    run.add_sample(Sample(id="s1", sample_id="OTH1", lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, OTHER)


def _save_box(client, run_id, sid, field, value, shown):
    """One row box saving, as the page sends it."""
    return client.post(f"/runs/{run_id}/samples/{sid}/settings",
                       data={field: value, "target_setting": shown}, headers=ORIGIN)


def _mismatches(ctx, run_id, sid):
    sample = ctx.run_repo.get_by_id(run_id).get_sample(sid)
    return sample.barcode_mismatches_index1, sample.barcode_mismatches_index2


def _in_threads(client, *calls):
    """Start each call on its own thread, all sharing the client's one event
    loop, as in the app; return their results and the threads."""
    results = [dict() for _ in calls]
    threads = [threading.Thread(target=lambda r=r, c=c: r.update(answer=c()))
               for r, c in zip(results, calls)]
    return results, threads


def _routes(routes, prefix=""):
    for route in routes:
        if isinstance(route, Mount) and getattr(route.app, "routes", None):
            yield from _routes(route.app.routes, prefix + route.path)
        elif getattr(route, "original_router", None) is not None:
            # FastAPI keeps an included router as one entry that points at it.
            included = getattr(route.include_context, "prefix", "") or ""
            yield from _routes(route.original_router.routes, prefix + included)
        elif isinstance(route, APIRoute):
            yield prefix + route.path, route.endpoint


class TestNoRouteRunsOnTheLoop:
    def test_every_route_of_seqsetup_is_a_plain_def(self, fresh_app):
        app, _ctx, _db = fresh_app
        on_the_loop = sorted(
            f"{path} {endpoint.__module__}.{endpoint.__name__}"
            for path, endpoint in _routes(app.routes)
            if endpoint.__module__.startswith("seqsetup") and inspect.iscoroutinefunction(endpoint))
        assert on_the_loop == []

    def test_the_walk_finds_the_routes(self, fresh_app):
        """Control: the walk above reaches the app's routes, the API's
        included, so an empty list means something."""
        app, _ctx, _db = fresh_app
        paths = {path for path, _endpoint in _routes(app.routes)}
        assert "/runs/{run_id}/samples/{sample_id}/settings" in paths
        assert any(path.startswith("/api/") for path in paths), sorted(paths)[:20]


class TestOthersAreServedWhileAnEditSaves:
    def test_a_page_loads_while_a_row_save_is_held(self, logged_in_client, two_rows, monkeypatch):
        ctx = two_rows
        real_save = ctx.run_repo.save
        saving, go_on = threading.Event(), threading.Event()

        def held_save(run):
            saving.set()
            go_on.wait(timeout=30)
            return real_save(run)

        monkeypatch.setattr(ctx.run_repo, "save", held_save)
        (edit, visit), (editor, visitor) = _in_threads(
            logged_in_client,
            lambda: _save_box(logged_in_client, RUN, "s1", "barcode_mismatches_index1", "0", "1"),
            lambda: logged_in_client.get("/"),
        )
        with logged_in_client:
            editor.start()
            try:
                assert saving.wait(timeout=30), "the edit never reached its save"
                visitor.start()
                visitor.join(timeout=5)
                served_meanwhile = not visitor.is_alive()
            finally:
                go_on.set()
                editor.join(timeout=60)
                if visitor.ident:
                    visitor.join(timeout=60)

        assert served_meanwhile, "no page could load while one edit was saving"
        assert visit["answer"].status_code == 200
        assert edit["answer"].status_code == 200, edit["answer"].text[:300]
        assert _mismatches(ctx, RUN, "s1") == (0, 1)

    def test_an_edit_of_another_run_lands_while_one_is_held(self, logged_in_client, two_rows,
                                                            monkeypatch):
        """The turn is the run's, not the app's."""
        ctx = two_rows
        _other_run(ctx)
        real_save = ctx.run_repo.save
        saving, go_on = threading.Event(), threading.Event()

        def held_save(run):
            if run.id == RUN:
                saving.set()
                go_on.wait(timeout=30)
            return real_save(run)

        monkeypatch.setattr(ctx.run_repo, "save", held_save)
        (held, other), (holder, mover) = _in_threads(
            logged_in_client,
            lambda: _save_box(logged_in_client, RUN, "s1", "barcode_mismatches_index1", "0", "1"),
            lambda: _save_box(logged_in_client, OTHER, "s1", "barcode_mismatches_index1", "2", "1"),
        )
        with logged_in_client:
            holder.start()
            try:
                assert saving.wait(timeout=30), "the first edit never reached its save"
                mover.start()
                mover.join(timeout=5)
                landed_meanwhile = not mover.is_alive()
            finally:
                go_on.set()
                holder.join(timeout=60)
                if mover.ident:
                    mover.join(timeout=60)

        assert landed_meanwhile, "an edit of another run waited for this one"
        assert other["answer"].status_code == 200, other["answer"].text[:300]
        assert held["answer"].status_code == 200, held["answer"].text[:300]
        assert _mismatches(ctx, OTHER, "s1") == (2, 1)
        assert _mismatches(ctx, RUN, "s1") == (0, 1)


class TestOnePersonsQuickSavesBothLand:
    """Two row boxes of one run saved a split second apart: both are stored.
    Without the run's turn the second loads the run while the first is still
    saving it, and then loses the version check -- the regression measured
    when F9 was first tried (200/409)."""

    def test_two_rows_saved_at_once(self, logged_in_client, two_rows, monkeypatch):
        ctx = two_rows
        real_save, real_get = ctx.run_repo.save, ctx.run_repo.get_by_id
        first_saving, second_loaded = threading.Event(), threading.Event()

        def get(run_id):
            if first_saving.is_set():
                second_loaded.set()
            return real_get(run_id)

        def save(run):
            if not first_saving.is_set():
                first_saving.set()
                # Without a turn the second request loads the run now; with
                # one it cannot, and this save goes on after a moment.
                second_loaded.wait(timeout=1.5)
            return real_save(run)

        monkeypatch.setattr(ctx.run_repo, "get_by_id", get)
        monkeypatch.setattr(ctx.run_repo, "save", save)
        (one, two), (first, second) = _in_threads(
            logged_in_client,
            lambda: _save_box(logged_in_client, RUN, "s1", "barcode_mismatches_index1", "0", "1"),
            lambda: _save_box(logged_in_client, RUN, "s2", "barcode_mismatches_index2", "2", "1"),
        )
        with logged_in_client:
            first.start()
            try:
                assert first_saving.wait(timeout=30), "the first save never started"
                second.start()
            finally:
                first.join(timeout=60)
                second.join(timeout=60)

        assert one["answer"].status_code == 200, one["answer"].text[:300]
        assert two["answer"].status_code == 200, two["answer"].text[:300]
        assert _mismatches(ctx, RUN, "s1") == (0, 1)
        assert _mismatches(ctx, RUN, "s2") == (1, 2)


class TestATurnThatDoesNotComeIsRefused:
    def test_the_second_save_is_refused_and_changes_nothing(self, logged_in_client, two_rows,
                                                            monkeypatch):
        from seqsetup.services import run_turns
        monkeypatch.setattr(run_turns, "TURN_WAIT_SECONDS", 0.3)
        ctx = two_rows
        real_save = ctx.run_repo.save
        saving, go_on = threading.Event(), threading.Event()

        def held_save(run):
            if not saving.is_set():
                saving.set()
                go_on.wait(timeout=30)
            return real_save(run)

        monkeypatch.setattr(ctx.run_repo, "save", held_save)
        (one, two), (first, second) = _in_threads(
            logged_in_client,
            lambda: _save_box(logged_in_client, RUN, "s1", "barcode_mismatches_index1", "0", "1"),
            lambda: _save_box(logged_in_client, RUN, "s2", "barcode_mismatches_index2", "2", "1"),
        )
        with logged_in_client:
            first.start()
            try:
                assert saving.wait(timeout=30), "the first save never started"
                second.start()
                second.join(timeout=10)
                refused_meanwhile = not second.is_alive()
            finally:
                go_on.set()
                first.join(timeout=60)
                if second.ident:
                    second.join(timeout=60)

        assert refused_meanwhile, "the second save waited without end"
        assert two["answer"].status_code == 409
        assert "still being saved" in two["answer"].text
        assert "Nothing was changed" in two["answer"].text
        assert one["answer"].status_code == 200, one["answer"].text[:300]
        assert _mismatches(ctx, RUN, "s1") == (0, 1)
        assert _mismatches(ctx, RUN, "s2") == (1, 1)


class TestARouteThatSavesNothingTakesNoTurn:
    """The LIMS list waits on the LIMS, up to its socket timeout per read.
    Holding the run's turn meanwhile would make the person's own saves wait,
    and be refused after a minute (fresh review of 057748e, P3-2)."""

    def test_a_row_save_lands_while_the_lims_list_waits(self, logged_in_client, two_rows, monkeypatch):
        from seqsetup.models.sample_api_config import SampleApiConfig
        from seqsetup.services import sample_api
        ctx = two_rows
        ctx.sample_api_config_repo.save(SampleApiConfig(base_url="https://lims.example.org/api",
                                                        enabled=True))
        asking, answer = threading.Event(), threading.Event()

        def slow_lims(config):
            asking.set()
            answer.wait(timeout=30)
            return False, "The LIMS did not answer", [], []

        monkeypatch.setattr(sample_api, "fetch_worklists", slow_lims)
        (listed, saved), (lister, saver) = _in_threads(
            logged_in_client,
            lambda: logged_in_client.get(f"/runs/{RUN}/samples/worklists"),
            lambda: _save_box(logged_in_client, RUN, "s1", "barcode_mismatches_index1", "0", "1"),
        )
        with logged_in_client:
            lister.start()
            try:
                assert asking.wait(timeout=30), "the list never asked the LIMS"
                saver.start()
                saver.join(timeout=5)
                landed_meanwhile = not saver.is_alive()
            finally:
                answer.set()
                lister.join(timeout=60)
                if saver.ident:
                    saver.join(timeout=60)

        assert landed_meanwhile, "a row save waited for the LIMS list"
        assert saved["answer"].status_code == 200, saved["answer"].text[:300]
        assert listed["answer"].status_code == 200
        assert _mismatches(ctx, RUN, "s1") == (0, 1)


class TestMarkReadyStartsFromTheSavesInLine:
    """Mark Ready takes no turn -- it may run for minutes -- but it waits for
    the saves already in line, so it checks and writes the run they leave.
    Started from the run before a save still landing, it ran the checks and
    drew the report, then lost the version check at the end: "modified by
    another user" for the person's own edit (fresh review of 057748e, P3-1)."""

    def test_mark_ready_pressed_while_a_save_is_landing(self, logged_in_client, fresh_app, monkeypatch):
        from seqsetup.models.sequencing_run import RunStatus
        from .conftest import mark_ready, seed_profiles
        from .test_scheduled_sync_instrument_cache import _scheduled_sync, _seed_run
        _app, ctx, _db = fresh_app
        profiles = seed_profiles(ctx, lane=False)
        _scheduled_sync(ctx, monkeypatch, "forward", profiles)
        run_id = _seed_run(ctx, "f9-mark-ready")
        sid = ctx.run_repo.get_by_id(run_id).samples[0].id
        real_save, real_get = ctx.run_repo.save, ctx.run_repo.get_by_id
        edit_saving, ready_loaded = threading.Event(), threading.Event()

        def get(some_id):
            if edit_saving.is_set():
                ready_loaded.set()
            return real_get(some_id)

        def save(run):
            if not edit_saving.is_set():
                edit_saving.set()
                # Without the wait Mark Ready loads the run now; with it, it
                # cannot, and this save goes on after a moment.
                ready_loaded.wait(timeout=1.5)
            return real_save(run)

        monkeypatch.setattr(ctx.run_repo, "get_by_id", get)
        monkeypatch.setattr(ctx.run_repo, "save", save)
        (edit, ready), (editor, presser) = _in_threads(
            logged_in_client,
            lambda: _save_box(logged_in_client, run_id, sid, "barcode_mismatches_index1", "0", "1"),
            lambda: mark_ready(logged_in_client, run_id, ORIGIN),
        )
        with logged_in_client:
            editor.start()
            try:
                assert edit_saving.wait(timeout=30), "the edit never reached its save"
                presser.start()
            finally:
                editor.join(timeout=60)
                presser.join(timeout=180)

        assert edit["answer"].status_code == 200, edit["answer"].text[:300]
        assert ready["answer"].status_code == 200, ready["answer"].text[:300]
        stored = real_get(run_id)
        assert stored.status == RunStatus.READY, ready["answer"].text[:500]
        assert stored.samples[0].barcode_mismatches_index1 == 0

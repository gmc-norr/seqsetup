"""The deleted-runs page lists everything even when a run cannot be read.

``services/deleted_runs.visible_rows`` loaded a whole run through
``run_repo.get_by_id`` only to see whether it still exists, for a run with a
pending copy whose delete never finished. Reading a run runs every model
check, so one damaged document -- a run naming an instrument this release
does not know (``stored_platform``, 2026-10-17) -- made
``/admin/deleted-runs`` fail for every administrator, and the page that
exists to account for deletions was the one page they could not open.

The existence question is asked as an existence question: a thin
``RunRepository.exists(run_id)``.
"""

import pytest

from seqsetup.models.deleted_run import DeletedRun
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (InstrumentPlatform, RunCycles, RunStatus,
                                            SequencingRun)
from seqsetup.services.deleted_runs import DELETED, NOT_CONFIRMED, visible_rows
from seqsetup.utils.clock import utcnow

UNKNOWN = "NovaSeq Z Series"


def _run(ctx, run_id, status=RunStatus.READY):
    run = SequencingRun(id=run_id, run_name=run_id,
                        instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10),
                        status=status)
    run.add_sample(Sample(id=f"{run_id}-s1", sample_id="PAT-1", lanes=[1]))
    ctx.run_repo.save(run)
    return run


def _pending_copy(ctx, run, copy_id, by="admin-test"):
    copy = DeletedRun.of(run, deleted_by=by, at=utcnow())
    copy.copy_id = copy_id
    ctx.deleted_run_repo.start(copy)
    return copy


def _damage(db, run_id):
    db["runs"].update_one({"_id": run_id}, {"$set": {"instrument_platform": UNKNOWN}})


class TestThePageSurvivesADamagedRun:

    def test_the_rows_are_built_without_reading_the_run(self, fresh_app):
        _app, ctx, db = fresh_app
        run = _run(ctx, "damaged")
        _pending_copy(ctx, run, "copy-1")
        _damage(db, "damaged")

        rows = visible_rows(ctx.deleted_run_repo, ctx.run_repo)

        # The run still exists, so a delete that did not finish shows no row.
        assert rows == []

    def test_a_damaged_run_that_is_gone_is_listed_as_not_confirmed(self, fresh_app):
        _app, ctx, db = fresh_app
        run = _run(ctx, "gone")
        _pending_copy(ctx, run, "copy-1")
        ctx.run_repo.collection.delete_one({"_id": "gone"})

        (row,) = visible_rows(ctx.deleted_run_repo, ctx.run_repo)

        assert (row["run_id"], row["shown_state"]) == ("gone", NOT_CONFIRMED)

    def test_one_damaged_run_does_not_hide_the_other_rows(self, fresh_app):
        _app, ctx, db = fresh_app
        damaged = _run(ctx, "damaged")
        _pending_copy(ctx, damaged, "copy-damaged")
        _damage(db, "damaged")
        finished = _run(ctx, "finished")
        copy = _pending_copy(ctx, finished, "copy-finished")
        ctx.deleted_run_repo.mark_completed(copy.copy_id, utcnow())
        ctx.run_repo.collection.delete_one({"_id": "finished"})

        rows = visible_rows(ctx.deleted_run_repo, ctx.run_repo)

        assert [(r["run_id"], r["shown_state"]) for r in rows] == [("finished", DELETED)]

    def test_the_page_opens(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        run = _run(ctx, "damaged")
        _pending_copy(ctx, run, "copy-1")
        _damage(db, "damaged")
        finished = _run(ctx, "finished")
        copy = _pending_copy(ctx, finished, "copy-finished")
        ctx.deleted_run_repo.mark_completed(copy.copy_id, utcnow())
        ctx.run_repo.collection.delete_one({"_id": "finished"})

        page = logged_in_client.get("/admin/deleted-runs")

        assert page.status_code == 200
        assert "finished" in page.text

    def test_nothing_is_written(self, fresh_app):
        _app, ctx, db = fresh_app
        run = _run(ctx, "damaged")
        _pending_copy(ctx, run, "copy-1")
        _damage(db, "damaged")
        before = {name: list(db[name].find()) for name in db.list_collection_names()}

        visible_rows(ctx.deleted_run_repo, ctx.run_repo)

        assert {name: list(db[name].find()) for name in db.list_collection_names()} == before


class TestExistsAsksOnlyWhetherTheDocumentIsThere:
    """A thin repository method: no model, no business logic
    (CLAUDE.md -- repositories are thin data access layers)."""

    def test_true_for_a_stored_run(self, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "there")

        assert ctx.run_repo.exists("there") is True

    def test_false_for_a_run_that_is_not_stored(self, fresh_app):
        _app, ctx, _db = fresh_app

        assert ctx.run_repo.exists("nowhere") is False

    def test_false_while_another_run_is_stored(self, fresh_app):
        """It must ask about the one id, not whether any run exists: a count
        over the whole collection would call every missing run present."""
        _app, ctx, _db = fresh_app
        _run(ctx, "somebody-else")

        assert ctx.run_repo.exists("nowhere") is False
        assert ctx.run_repo.exists("somebody-else") is True

    def test_true_for_a_run_that_cannot_be_read(self, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, "damaged")
        _damage(db, "damaged")

        assert ctx.run_repo.exists("damaged") is True
        with pytest.raises(ValueError):
            ctx.run_repo.get_by_id("damaged")

"""An archived run offers no button that cannot work, and Archive asks first.

``_run_status_bar.html`` showed **Reset to Draft** on an archived run although
ARCHIVED is terminal (``check_status_transition``): pressing it was refused
outright, with an error banner and a toast, so the page offered an action that
could only ever fail. And **Archive** had no confirmation although archiving
cannot be undone -- the only way to sequence the run again is to build a new
one.

The user chose (2026-10-18): no Reset to Draft on an archived run, and Archive
asks first. The route still refuses ARCHIVED -> DRAFT, whoever asks.
"""

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (InstrumentPlatform, RunCycles, RunStatus,
                                            SequencingRun)

ORIGIN = {"Origin": "http://testserver"}


def _run(ctx, run_id, status):
    run = SequencingRun(id=run_id, run_name=run_id,
                        instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10),
                        status=status)
    run.add_sample(Sample(id=f"{run_id}-s1", sample_id="PAT-1", lanes=[1]))
    ctx.run_repo.save(run)
    return run


def _form_tag(page: str, action: str) -> str:
    """The opening ``<form>`` tag of the form that posts to ``action``.

    Sliced from the ``<form`` before the action to the ``>`` that closes that
    tag, so an attribute on a *different* form cannot satisfy the assertion.
    An earlier helper sliced "the status bar" and silently returned most of
    the page, which made ``assert "hx-confirm" in bar`` pass however the
    template was written (review of f77a5b0, P3).
    """
    at = page.index(action)
    start = page.rindex("<form", 0, at)
    tag = page[start:page.index(">", start) + 1]
    assert action in tag, tag
    return tag


class TestAnArchivedRunOffersNoDeadButton:

    def test_no_reset_to_draft_button(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "arc", RunStatus.ARCHIVED)

        page = logged_in_client.get("/runs/arc").text

        assert "Reset to Draft" not in page
        assert f"/runs/arc/status/draft" not in page

    def test_the_bar_says_the_run_is_archived_and_why_there_is_no_button(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "arc", RunStatus.ARCHIVED)

        page = logged_in_client.get("/runs/arc").text

        assert ">Archived<" in page
        assert "cannot be changed" in page

    def test_the_route_still_refuses_archived_to_draft(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, "arc", RunStatus.ARCHIVED)

        answer = logged_in_client.post("/runs/arc/status/draft", headers=ORIGIN)

        assert answer.status_code == 400
        assert "archived" in answer.text and "draft" in answer.text
        assert db["runs"].find_one({"_id": "arc"})["status"] == "archived"

    @pytest.mark.parametrize("target", ["ready", "archived"])
    def test_the_route_refuses_every_transition_out_of_archived(
            self, logged_in_client, fresh_app, target):
        _app, ctx, db = fresh_app
        _run(ctx, "arc", RunStatus.ARCHIVED)

        answer = logged_in_client.post(f"/runs/arc/status/{target}", headers=ORIGIN)

        assert answer.status_code == 400, answer.text
        assert db["runs"].find_one({"_id": "arc"})["status"] == "archived"


class TestArchiveAsksFirst:

    def test_the_archive_button_confirms(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "rdy", RunStatus.READY)

        page = logged_in_client.get("/runs/rdy").text
        tag = _form_tag(page, "/runs/rdy/status/archived")

        assert "hx-confirm" in tag, tag
        assert "cannot be changed" in tag and "cannot be returned to Draft" in tag, tag

    def test_return_to_draft_does_not_confirm(self, logged_in_client, fresh_app):
        """It can be undone by marking the run Ready again, so it asks nothing
        -- only the one-way change does. The tag is sliced exactly, so the
        Archive form's confirm a few lines below cannot satisfy this."""
        _app, ctx, _db = fresh_app
        _run(ctx, "rdy", RunStatus.READY)

        page = logged_in_client.get("/runs/rdy").text
        tag = _form_tag(page, "/runs/rdy/status/draft")

        assert "hx-confirm" not in tag, tag

    def test_a_ready_run_still_offers_both(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "rdy", RunStatus.READY)

        page = logged_in_client.get("/runs/rdy").text

        assert "Return to Draft" in page and ">Archive<" in page

    def test_archiving_still_works(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, "rdy", RunStatus.READY)

        answer = logged_in_client.post("/runs/rdy/status/archived", headers=ORIGIN)

        assert answer.status_code == 200, answer.text
        assert db["runs"].find_one({"_id": "rdy"})["status"] == "archived"
        assert "Reset to Draft" not in answer.text


class TestEveryWayToArchiveAsksTheSameQuestion:
    """``routes/runs.py`` and ``routes/dashboard.py`` are the only two places
    that set ARCHIVED. The dashboard's button asked a bare "Archive this
    run?" for the same one-way change, on the surface where a misclick lands
    on the wrong row (review of f77a5b0, P2-1)."""

    def test_the_dashboard_button_names_the_run_and_the_consequence(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _run(ctx, "rdy", RunStatus.READY)
        run.run_name = "Patient batch 7"
        ctx.run_repo.save(run)

        # The row with the Archive button is on the Ready tab, not the
        # dashboard's default one.
        page = logged_in_client.get("/dashboard/tab/ready").text
        at = page.index("/runs/rdy/archive")
        tag = page[page.rindex("<button", 0, at):page.index(">", at)]

        assert "Patient batch 7" in tag, tag
        assert "cannot be changed" in tag and "cannot be returned to Draft" in tag, tag

    def test_a_run_with_no_name_still_reads(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _run(ctx, "rdy", RunStatus.READY)
        run.run_name = ""
        ctx.run_repo.save(run)

        # The row with the Archive button is on the Ready tab, not the
        # dashboard's default one.
        page = logged_in_client.get("/dashboard/tab/ready").text
        at = page.index("/runs/rdy/archive")
        tag = page[page.rindex("<button", 0, at):page.index(">", at)]

        assert "Archive this run?" in tag, tag


class TestAnArchivedRunIsNotToldToReturnToDraft:
    """``_sample_section.html``'s read-only note covered READY and ARCHIVED
    together, so an archived run read "Return to Draft to make changes" a few
    hundred pixels below the status bar saying it cannot be returned to Draft
    (review of f77a5b0, P2-2)."""

    def test_an_archived_run_says_it_cannot_be_changed(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "arc", RunStatus.ARCHIVED)

        page = logged_in_client.get("/runs/arc").text

        assert "Return to Draft to make changes" not in page
        assert "This run is archived" in page

    def test_a_ready_run_is_still_told_to_return_to_draft(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "rdy", RunStatus.READY)

        page = logged_in_client.get("/runs/rdy").text

        assert "Return to Draft to make changes" in page

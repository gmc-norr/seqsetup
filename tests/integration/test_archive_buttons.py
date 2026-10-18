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


def _status_bar(page: str) -> str:
    bar = page[page.index('id="run-status-bar"'):]
    return bar[:bar.index("</div>\n</div>") + 12] if "</div>\n</div>" in bar else bar


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
        bar = _status_bar(page)

        archive = bar[bar.index("/runs/rdy/status/archived") - 400:]
        archive = archive[:archive.index("Archive<") + 8]
        assert "hx-confirm" in archive, archive
        assert "cannot be changed" in archive and "Draft" in archive, archive

    def test_return_to_draft_does_not_confirm(self, logged_in_client, fresh_app):
        """It can be undone by marking the run Ready again, so it asks nothing
        -- only the one-way change does."""
        _app, ctx, _db = fresh_app
        _run(ctx, "rdy", RunStatus.READY)

        page = logged_in_client.get("/runs/rdy").text
        form = page[page.index("/runs/rdy/status/draft") - 300:]
        form = form[:form.index("Return to Draft<")]

        assert "hx-confirm" not in form, form

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

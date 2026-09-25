"""The run page does not shout about things that are simply not done yet.

A new run with no samples used to show a red "1 error" in the step bar
and the Check box, and a draft's Export box showed four dead buttons and
an orange warning. Neither is an error to fix: the step just hasn't been
reached. Real errors still show red, and Mark Ready still refuses a run
with no samples.
"""

import re

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun


def _run(ctx, run_id, *, samples=(), status=RunStatus.DRAFT, flowcell="10B"):
    run = SequencingRun(
        id=run_id, run_name="Calm run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type=flowcell,
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
    )
    for s in samples:
        run.add_sample(s)
    ctx.run_repo.save(run)
    return run_id


def _check_step(html):
    m = re.search(r'<li[^>]*data-step="check"[^>]*data-state="(\w+)"', html)
    return m.group(1)


class TestEmptyRunCheck:
    """With no samples yet, Check waits in grey instead of showing an error."""

    def test_step_bar_check_waits(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "empty-run")
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert _check_step(page) == "todo"
        bar = page.split('id="run-step-bar"', 1)[1].split("</nav>", 1)[0]
        assert "1 error" not in bar

    def test_check_box_says_add_samples_first(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "empty-run")
        panel = logged_in_client.get(f"/runs/{run_id}/validate-panel").text
        assert "Add samples first" in panel
        assert "has-errors" not in panel
        assert "Errors:" not in panel

    def test_other_errors_on_an_empty_run_still_show(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        # No run name: a second error besides "no samples".
        run_id = _run(ctx, "empty-unnamed-run")
        run = ctx.run_repo.get_by_id(run_id)
        run.run_name = ""
        ctx.run_repo.save(run)
        page = logged_in_client.get(f"/runs/{run_id}").text
        panel = logged_in_client.get(f"/runs/{run_id}/validate-panel").text
        assert _check_step(page) == "error"
        assert "has-errors" in panel and "Errors: 2" in panel

    def test_mark_ready_still_refuses_an_empty_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "empty-run")
        logged_in_client.post(f"/runs/{run_id}/status/ready", headers={"Origin": "http://testserver"})
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT

    def test_run_with_samples_and_errors_is_still_red(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "lane9-run", samples=[Sample(id="s1", sample_id="S1", lanes=[9])])
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert _check_step(page) == "error"
        assert "has-errors" in logged_in_client.get(f"/runs/{run_id}/validate-panel").text


class TestExportBeforeReady:
    """A draft's Export box is one line, not four dead buttons."""

    def test_draft_shows_one_line(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "draft-run")
        page = logged_in_client.get(f"/runs/{run_id}").text
        export = page.split('id="export-panel"', 1)[1].split("</fieldset>", 1)[0]
        assert "Downloads open when the run is Ready." in export
        assert "Download Sample Sheet" not in export

    def test_ready_run_keeps_its_buttons(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "ready-run", status=RunStatus.READY)
        page = logged_in_client.get(f"/runs/{run_id}").text
        export = page.split('id="export-panel"', 1)[1].split("</fieldset>", 1)[0]
        assert f'href="/runs/{run_id}/export/samplesheet-v2"' in export or "Download Sample Sheet v2" in export


class TestValidationPageBackLink:
    """One way back to the run, not two."""

    def test_single_back_link(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "val-run", samples=[Sample(id="s1", sample_id="S1", lanes=[1])])
        page = logged_in_client.get(f"/runs/{run_id}/validation").text
        assert len(re.findall(r">\s*(?:← )?Back to [Rr]un\s*<", page)) == 1

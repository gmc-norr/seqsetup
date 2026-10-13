"""One tidy run page (the user's choice over tabs, 2026-10-12).

- Check sits inside "Samples and indexes", just below the samples. Above
  them, it moved every row each time it refreshed and changed height
  (300 ms after a change), so a quick drag could land on the wrong row.
  It stays outside #sample-section, which sample changes redraw; Check
  refreshes itself.
- Export shows only once the run is Ready. A draft keeps an empty, hidden
  #export-panel so the status change can swap the buttons in.
- Save as template and Change history share one closed "More" fold at the
  bottom; the history loads the first time it opens.
"""

import re

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock


def _run(ctx, run_id, status=RunStatus.DRAFT):
    run = SequencingRun(
        id=run_id, run_name="Layout run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
    )
    run.add_sample(Sample(id=f"{run_id}-s1", sample_id="L1", lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)
    return run_id


def _page(client, run_id):
    resp = client.get(f"/runs/{run_id}")
    assert resp.status_code == 200
    return resp.text


def _tag(html, marker):
    """The start tags that contain ``marker``."""
    return re.findall(r"<[a-z]+\b[^<>]*" + re.escape(marker) + r"[^<>]*>", html)


@pytest.mark.parametrize("status", [RunStatus.DRAFT, RunStatus.READY, RunStatus.ARCHIVED])
class TestCheckSitsBelowTheSamples:
    def test_check_comes_after_the_table(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        html = _page(logged_in_client, _run(ctx, f"check-{status.value}", status))
        samples = html.index('id="samples"')
        section = html.index('id="sample-section"')
        check = html.index('id="validate-panel"')
        export = html.index('id="export-panel"')
        assert samples < section < check < export

    def test_check_still_refreshes_itself(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, f"refresh-{status.value}", status)
        [panel] = _tag(_page(logged_in_client, run_id), 'id="validate-panel"')
        assert f'hx-get="/runs/{run_id}/validate-panel"' in panel


def test_a_section_redraw_leaves_check_alone(logged_in_client, fresh_app):
    """Check is outside #sample-section, so a change that redraws the
    section does not carry Check with it."""
    _app, ctx, _db = fresh_app
    run_id = _run(ctx, "redraw")
    resp = logged_in_client.post(
        f"/runs/{run_id}/samples/set-lanes",
        data={"sample_ids": f'["{run_id}-s1"]', "lanes": "[1]"},
        headers={"Origin": "http://testserver", "HX-Request": "true"},
    )
    assert resp.status_code == 200
    assert 'id="sample-section"' in resp.text
    assert 'id="validate-panel"' not in resp.text


class TestExportOnlyOnceReady:
    def test_a_draft_shows_no_export(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        html = _page(logged_in_client, _run(ctx, "export-draft"))
        [panel] = _tag(html, 'id="export-panel"')
        assert panel.startswith("<div")
        assert re.search(r"\shidden\b", panel)
        assert "Downloads open when the run is Ready." not in html
        assert "/export/samplesheet-v2" not in html
        assert "<legend>Export</legend>" not in html

    @pytest.mark.parametrize("status", [RunStatus.READY, RunStatus.ARCHIVED])
    def test_a_locked_run_shows_its_downloads(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, f"export-{status.value}", status)
        html = _page(logged_in_client, run_id)
        assert "<legend>Export</legend>" in html
        assert "Download Sample Sheet v2" in html

    def test_the_draft_placeholder_can_be_swapped(self, fresh_app):
        """Return to Draft swaps #export-panel out of band (routes/runs.py
        update_status), so the hidden placeholder carries hx-swap-oob too."""
        from seqsetup.templating import templates

        _app, ctx, _db = fresh_app
        run = ctx.run_repo.get_by_id(_run(ctx, "export-oob"))
        html = templates.env.get_template("runs/_export_panel.html").render(run=run, has_v1=False, oob=True)
        [panel] = _tag(html, 'id="export-panel"')
        assert 'hx-swap-oob="true"' in panel
        assert re.search(r"\shidden\b", panel)

    def test_the_status_change_swaps_export_in_and_out(self, logged_in_client, fresh_app):
        """Through the real route: Mark Ready swaps the downloads in, back
        to Draft swaps the hidden placeholder back, both out of band."""
        from .conftest import disable_repos, mark_ready
        from .test_group_1c import _pair

        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = SequencingRun(
            id="export-swap", run_name="Export swap run",
            instrument_platform=InstrumentPlatform.NOVASEQ_6000, flowcell_type="S4",
            run_cycles=RunCycles(151, 151, 10, 10),
        )
        run.add_sample(Sample(sample_id="S1", index_pair=_pair("CCCCCCCC", "GGGGGGGG", "p1"), lanes=[1]))
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, run.id)
        origin = {"Origin": "http://testserver"}

        ready = mark_ready(logged_in_client, run.id, origin)
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.READY
        [panel] = _tag(ready.text, 'id="export-panel"')
        assert 'hx-swap-oob="true"' in panel and not re.search(r"\shidden\b", panel)
        assert "Download Sample Sheet v2" in ready.text

        draft = logged_in_client.post(f"/runs/{run.id}/status/draft", headers=origin)
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT
        [panel] = _tag(draft.text, 'id="export-panel"')
        assert 'hx-swap-oob="true"' in panel and re.search(r"\shidden\b", panel)
        assert "Download Sample Sheet" not in draft.text


def _export_step_href(html):
    [step] = re.findall(r'<li[^>]*data-step="export".*?</li>', html, re.S)
    return re.search(r'href="([^"]*)"', step).group(1)


class TestExportStepLink:
    """The step bar's Export step goes where something can be done: Mark
    Ready on a draft (its Export box is a hidden placeholder), the
    downloads once Ready."""

    def test_on_a_draft_it_points_to_mark_ready(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        assert _export_step_href(_page(logged_in_client, _run(ctx, "step-draft"))) == "#run-status-bar"

    @pytest.mark.parametrize("status", [RunStatus.READY, RunStatus.ARCHIVED])
    def test_on_a_locked_run_it_points_to_the_downloads(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        html = _page(logged_in_client, _run(ctx, f"step-{status.value}", status))
        assert _export_step_href(html) == "#export-panel"


@pytest.mark.parametrize("status", [RunStatus.DRAFT, RunStatus.READY, RunStatus.ARCHIVED])
class TestMoreFold:
    def test_template_and_history_share_one_closed_fold(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, f"more-{status.value}", status)
        html = _page(logged_in_client, run_id)
        [fold] = _tag(html, f'hx-get="/runs/{run_id}/history"')
        assert fold.startswith("<details")
        assert not re.search(r"\sopen\b", fold)
        assert 'hx-trigger="toggle once"' in fold
        inside = html.split(fold, 1)[1].split("</details>", 1)[0]
        assert "More: Save as template · Change history" in inside
        assert f'action="/runs/{run_id}/save-as-template"' in inside
        assert 'class="run-history-panel' in inside

    def test_no_separate_boxes_for_them(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        html = _page(logged_in_client, _run(ctx, f"nobox-{status.value}", status))
        assert "<legend>Save as template</legend>" not in html
        assert "<legend>Change history</legend>" not in html
        assert html.index('id="validate-panel"') < html.index("More: Save as template")

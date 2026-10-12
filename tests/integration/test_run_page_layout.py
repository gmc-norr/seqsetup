"""One tidy run page (the user's choice over tabs, 2026-10-12).

- Check sits inside "Samples and indexes", just above the samples, so its
  errors show where they are fixed. It stays outside #sample-section,
  which sample changes redraw; Check refreshes itself.
- Export shows only once the run is Ready. A draft keeps an empty, hidden
  #export-panel so the status change can swap the buttons in.
- Save as template and Change history share one closed "More" fold at the
  bottom; the history loads the first time it opens.
"""

import re

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun


def _run(ctx, run_id, status=RunStatus.DRAFT):
    run = SequencingRun(
        id=run_id, run_name="Layout run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
    )
    run.add_sample(Sample(id=f"{run_id}-s1", sample_id="L1", lanes=[1]))
    ctx.run_repo.save(run)
    return run_id


def _page(client, run_id):
    resp = client.get(f"/runs/{run_id}")
    assert resp.status_code == 200
    return resp.text


def _tag(html, marker):
    """The start tags that contain ``marker``."""
    return re.findall(r"<[a-z]+\b[^<>]*" + re.escape(marker) + r"[^<>]*>", html)


@pytest.mark.parametrize("status", [RunStatus.DRAFT, RunStatus.READY, RunStatus.ARCHIVED])
class TestCheckSitsAboveTheSamples:
    def test_check_is_inside_samples_before_the_table(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        html = _page(logged_in_client, _run(ctx, f"check-{status.value}", status))
        samples = html.index('id="samples"')
        check = html.index('id="validate-panel"')
        section = html.index('id="sample-section"')
        assert samples < check < section

    def test_check_still_refreshes_itself(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, f"refresh-{status.value}", status)
        [panel] = _tag(_page(logged_in_client, run_id), 'id="validate-panel"')
        assert f'hx-get="/runs/{run_id}/validate-panel"' in panel


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

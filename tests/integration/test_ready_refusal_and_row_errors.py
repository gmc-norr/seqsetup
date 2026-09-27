"""A refused Mark Ready lists every error, and the run page knows which
samples each error names.

The refusal used to squeeze at most three errors into one paragraph and
hide the rest behind "(+ N more)". It is now a list of all of them, with
a link to the validation page. The Validate box carries the per-sample
errors so the page can mark those rows.
"""

import json
import re

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.services.validation import ValidationService, clear_validation_cache

ORIGIN = {"Origin": "http://testserver", "HX-Request": "true"}


def _pair(n, i7, i5):
    return IndexPair(
        id=f"p{n}", name=f"P{n}",
        index1=Index(name=f"i7-{n}", sequence=i7, index_type=IndexType.I7),
        index2=Index(name=f"i5-{n}", sequence=i5, index_type=IndexType.I5),
    )


def _make_bad_run(ctx):
    """Two samples collide in lane 1, one sits on lane 9 of an 8-lane
    flowcell, one has a clean index."""
    run = SequencingRun(
        id="refusal-run", run_name="Refusal run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
    )
    run.add_sample(Sample(id="s-a", sample_id="A", lanes=[1], index_pair=_pair(1, "ATTACTCG", "TATAGCCT")))
    run.add_sample(Sample(id="s-b", sample_id="B", lanes=[1], index_pair=_pair(2, "ATTACTCG", "TATAGCCT")))
    run.add_sample(Sample(id="s-l9", sample_id="LANE9", lanes=[9], index_pair=_pair(3, "TCCGGAGA", "ATAGAGGC")))
    run.add_sample(Sample(id="s-ok", sample_id="OK", lanes=[2], index_pair=_pair(4, "CGCTCATT", "CCTATCCT")))
    ctx.run_repo.save(run)
    return run.id


def _error_count(ctx, run_id):
    clear_validation_cache()
    return ValidationService.validate_run(
        ctx.run_repo.get_by_id(run_id),
        test_profile_repo=ctx.test_profile_repo,
        app_profile_repo=ctx.app_profile_repo,
        instrument_config=ctx.instrument_config,
    ).error_count


class TestReadyRefusal:
    """POST /runs/{id}/status/ready on a run with errors."""

    def test_lists_every_error(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_bad_run(ctx)
        count = _error_count(ctx, run_id)
        assert count > 3  # more than the old three-message cut-off

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)
        assert resp.status_code == 200
        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert len(re.findall(r"<li>", resp.text)) == count
        assert "more)" not in resp.text
        assert f"{count} error" in resp.text
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT

    def test_links_to_validation_page(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_bad_run(ctx)
        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)
        assert f'href="/runs/{run_id}/validation"' in resp.text

    def test_messages_are_escaped(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = SequencingRun(
            id="escape-run", run_name="Escape run",
            instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
        )
        run.add_sample(Sample(id="x", sample_id="<b>bad</b>", lanes=[9]))
        ctx.run_repo.save(run)
        resp = logged_in_client.post("/runs/escape-run/status/ready", headers=ORIGIN)
        assert "<b>bad</b>" not in resp.text
        assert "&lt;b&gt;bad&lt;/b&gt;" in resp.text


class TestPanelCarriesRowErrors:
    """The Validate box holds {sample id: [messages]} for the row marks."""

    def _errors(self, html):
        m = re.search(r"data-sample-errors='([^']*)'", html)
        assert m, "Validate box has no data-sample-errors"
        return json.loads(m.group(1).replace("&#39;", "'").replace("&quot;", '"'))

    def test_edit_page_panel_names_erroring_samples(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_bad_run(ctx)
        errors = self._errors(logged_in_client.get(f"/runs/{run_id}").text)
        assert any("collision" in m for m in errors["s-a"])
        assert any("collision" in m for m in errors["s-b"])
        # OK shares only the run-wide "no test_id" error, not these.
        assert not any("collision" in m or "lane 9" in m for m in errors.get("s-ok", []))

    def test_refreshed_panel_names_erroring_samples(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_bad_run(ctx)
        errors = self._errors(logged_in_client.get(f"/runs/{run_id}/validate-panel").text)
        assert any("lane 9" in m for m in errors["s-l9"])

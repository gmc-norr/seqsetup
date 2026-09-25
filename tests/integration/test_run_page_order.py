"""The run page follows the work: setup, samples and indexes, check, ready,
export.

It used to open with Validate and Export, then setup, then samples, so
the page read in a different order from the work. A step bar under the
run name now shows where the run stands and links to each part.
"""

import re

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun


def _pair(n, i7, i5):
    return IndexPair(
        id=f"p{n}", name=f"P{n}",
        index1=Index(name=f"i7-{n}", sequence=i7, index_type=IndexType.I7),
        index2=Index(name=f"i5-{n}", sequence=i5, index_type=IndexType.I5),
    )


def _run(ctx, run_id, *, name="Order run", samples=(), status=RunStatus.DRAFT):
    run = SequencingRun(
        id=run_id, run_name=name,
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
    )
    for s in samples:
        run.add_sample(s)
    ctx.run_repo.save(run)
    return run_id


def _steps(html):
    """{step key: (state, is_current)} from the step bar."""
    bar = html.split('id="run-step-bar"', 1)[1].split("</nav>", 1)[0]
    out = {}
    for m in re.finditer(r'<li[^>]*data-step="(\w+)"[^>]*data-state="(\w+)"([^>]*)>', bar):
        out[m.group(1)] = (m.group(2), 'aria-current="step"' in m.group(0))
    return out


class TestSectionOrder:
    """Parts of the page appear in the order the work happens."""

    def test_sections_in_work_order(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "order-run", samples=[Sample(id="s1", sample_id="S1")])
        html = logged_in_client.get(f"/runs/{run_id}").text
        markers = ['id="run-status-bar"', 'id="run-step-bar"', 'id="run-config-panel"',
                   'id="samples"', 'id="validate-panel"', 'id="export-panel"',
                   "Save as template", "Change history"]
        positions = [html.index(m) for m in markers]
        assert positions == sorted(positions), dict(zip(markers, positions))

    def test_header_shows_run_name(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "named-run", name="Header name run")
        assert re.search(r"<h1[^>]*>\s*Header name run\s*</h1>", logged_in_client.get(f"/runs/{run_id}").text)

    def test_unnamed_run_says_so(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "unnamed-run", name="")
        assert re.search(r"<h1[^>]*>\s*Untitled run\s*</h1>", logged_in_client.get(f"/runs/{run_id}").text)

    def test_setup_summary_lists_cycles_in_read_order(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "cycles-run")
        html = logged_in_client.get(f"/runs/{run_id}").text
        setup = html.split('id="run-config-panel"', 1)[1].split("</fieldset>", 1)[0]
        order = [setup.index(label) for label in ("Read 1", "Index 1", "Index 2", "Read 2")]
        assert order == sorted(order)
        assert "NovaSeq X" in setup and "10B" in setup

    def test_check_lists_errors(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "lane9-run", samples=[Sample(id="s1", sample_id="LANE9", lanes=[9])])
        panel = logged_in_client.get(f"/runs/{run_id}/validate-panel").text
        assert re.search(r"<li>[^<]*lane 9", panel)

    def test_check_list_is_capped_with_a_pointer(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        samples = [Sample(id=f"s{n}", sample_id=f"S{n}", lanes=[9]) for n in range(14)]
        run_id = _run(ctx, "many-errors-run", samples=samples)
        panel = logged_in_client.get(f"/runs/{run_id}/validate-panel").text
        assert len(re.findall(r"<li>", panel)) == 10
        assert "more on the validation page" in panel


class TestStepBar:
    """The step bar marks what is done and highlights the next step."""

    def test_empty_draft_is_on_samples(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "empty-run")
        steps = _steps(logged_in_client.get(f"/runs/{run_id}").text)
        assert steps["setup"] == ("done", False)
        assert steps["samples"] == ("todo", True)
        assert steps["export"][0] == "todo"

    def test_unnamed_draft_is_on_setup(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "noname-run", name="")
        steps = _steps(logged_in_client.get(f"/runs/{run_id}").text)
        assert steps["setup"] == ("todo", True)

    def test_unindexed_samples_are_on_indexes(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "noindex-run", samples=[Sample(id="s1", sample_id="S1", lanes=[1])])
        steps = _steps(logged_in_client.get(f"/runs/{run_id}").text)
        assert steps["samples"] == ("done", False)
        assert steps["indexes"] == ("todo", True)
        assert steps["check"][0] == "error"

    def test_indexed_with_errors_is_on_check(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        samples = [Sample(id="s1", sample_id="S1", lanes=[9], index_pair=_pair(1, "ATTACTCG", "TATAGCCT"))]
        run_id = _run(ctx, "check-run", samples=samples)
        steps = _steps(logged_in_client.get(f"/runs/{run_id}").text)
        assert steps["indexes"] == ("done", False)
        assert steps["check"] == ("error", True)

    @pytest.mark.parametrize("status", [RunStatus.READY, RunStatus.ARCHIVED])
    def test_locked_run_is_done(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        samples = [Sample(id="s1", sample_id="S1", lanes=[1], index_pair=_pair(1, "ATTACTCG", "TATAGCCT"))]
        run_id = _run(ctx, "locked-run", samples=samples, status=status)
        steps = _steps(logged_in_client.get(f"/runs/{run_id}").text)
        assert steps["ready"] == ("done", False)
        assert steps["export"] == ("done", False)
        # Nothing left to do on a locked run, even with a live error.
        assert not any(current for _state, current in steps.values())

    def test_steps_link_to_their_parts(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "links-run")
        html = logged_in_client.get(f"/runs/{run_id}").text
        bar = html.split('id="run-step-bar"', 1)[1].split("</nav>", 1)[0]
        for target in ("#run-config-panel", "#samples", "#validate-panel", "#run-status-bar", "#export-panel"):
            assert f'href="{target}"' in bar


class TestStepBarRoute:
    """GET /runs/{id}/step-bar re-renders the bar after each change."""

    def test_route_returns_current_steps(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "route-run")
        assert _steps(logged_in_client.get(f"/runs/{run_id}/step-bar").text)["samples"] == ("todo", True)

        run = ctx.run_repo.get_by_id(run_id)
        run.add_sample(Sample(id="s1", sample_id="S1", lanes=[1]))
        run.touch(updated_by="tester")
        ctx.run_repo.save(run)
        assert _steps(logged_in_client.get(f"/runs/{run_id}/step-bar").text)["samples"] == ("done", False)

    def test_missing_run_is_404(self, logged_in_client):
        assert logged_in_client.get("/runs/no-such-run/step-bar").status_code == 404

    def test_page_bar_refreshes_itself(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "refresh-run")
        html = logged_in_client.get(f"/runs/{run_id}").text
        assert f'hx-get="/runs/{run_id}/step-bar"' in html

"""Dashboard search: find a run by its name or by a sample ID in it.

"Which run is this sample in?" had no answer short of opening runs one by
one. The search box looks in every run (Draft, Ready and Archived) and
names the samples that matched. Read-only.
"""

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun


def _run(ctx, run_id, name, sample_ids=(), status=RunStatus.DRAFT):
    run = SequencingRun(
        id=run_id, run_name=name,
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
    )
    for n, sid in enumerate(sample_ids):
        run.add_sample(Sample(id=f"{run_id}-s{n}", sample_id=sid, lanes=[1]))
    ctx.run_repo.save(run)
    return run_id


def _search(client, q):
    return client.get("/dashboard/search", params={"q": q}).text


class TestDashboardSearch:
    """GET /dashboard/search?q= lists matching runs across all statuses."""

    def test_finds_run_by_name_ignoring_case(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "qs-alpha", "Qsearch Alpha")
        _run(ctx, "qs-beta", "Qsearch Beta")
        html = _search(logged_in_client, "qsearch alp")
        assert 'id="run-item-qs-alpha"' in html
        assert 'id="run-item-qs-beta"' not in html

    def test_finds_run_by_sample_id_and_names_the_sample(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "qs-samples", "Plain name", sample_ids=["PAT-12345", "PAT-99999"])
        html = _search(logged_in_client, "12345")
        assert 'id="run-item-qs-samples"' in html
        assert "PAT-12345" in html and "PAT-99999" not in html

    def test_looks_in_every_status(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "qs-draft", "Qstatus one")
        _run(ctx, "qs-ready", "Qstatus two", status=RunStatus.READY)
        _run(ctx, "qs-archived", "Qstatus three", status=RunStatus.ARCHIVED)
        html = _search(logged_in_client, "qstatus")
        for run_id in ("qs-draft", "qs-ready", "qs-archived"):
            assert f'id="run-item-{run_id}"' in html
        assert "status-ready" in html and "status-archived" in html

    def test_no_match_says_so(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "qs-any", "Anything")
        assert "No runs match" in _search(logged_in_client, "zz-no-such-run-qw")

    def test_empty_query_gives_back_the_tabs(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "qs-tabs", "Tabs run")
        html = _search(logged_in_client, "  ")
        assert 'hx-get="/dashboard/tab/ready"' in html
        assert "No runs match" not in html

    def test_query_is_escaped(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "qs-xss", "Plain")
        html = _search(logged_in_client, "<script>x</script>")
        assert "<script>x</script>" not in html
        assert "&lt;script&gt;" in html

    def test_dashboard_has_the_search_box(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "qs-box", "Box run")
        html = logged_in_client.get("/").text
        assert 'hx-get="/dashboard/search"' in html
        assert 'type="search"' in html

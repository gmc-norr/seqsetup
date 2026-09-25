"""The Validate box on the run page stays current.

It used to be computed once at page load, so after adding samples or
assigning indexes it kept showing the old counts and error total until
the page was reloaded. The box now re-fetches itself from
GET /runs/{id}/validate-panel after every successful change.
"""

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunStatus


def _make_run(ctx, status=RunStatus.DRAFT, samples=1):
    run = ctx.run_repo.create_run("tester")
    run = ctx.run_repo.get_by_id(run.id)
    run.run_name = "Panel run"
    for i in range(samples):
        run.add_sample(Sample(sample_id=f"S{i}"))
    run.status = status
    ctx.run_repo.save(run)
    return run.id


class TestValidatePanelRoute:
    """GET /runs/{id}/validate-panel renders the box from current data."""

    def test_panel_shows_current_sample_count(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, samples=1)
        assert "Samples: 1" in logged_in_client.get(f"/runs/{run_id}/validate-panel").text

        run = ctx.run_repo.get_by_id(run_id)
        run.add_sample(Sample(sample_id="S-new"))
        run.touch(updated_by="tester")
        ctx.run_repo.save(run)

        resp = logged_in_client.get(f"/runs/{run_id}/validate-panel")
        assert resp.status_code == 200
        assert "Samples: 2" in resp.text

    def test_panel_counts_errors_like_the_page(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, samples=0)
        page = logged_in_client.get(f"/runs/{run_id}").text
        panel = logged_in_client.get(f"/runs/{run_id}/validate-panel").text
        assert "No samples" in panel
        assert "Errors:" in page and "Errors:" in panel

    @pytest.mark.parametrize("status", [RunStatus.READY, RunStatus.ARCHIVED])
    def test_panel_available_for_locked_runs(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, status)
        resp = logged_in_client.get(f"/runs/{run_id}/validate-panel")
        assert resp.status_code == 200
        assert "Samples: 1" in resp.text

    def test_missing_run_is_404(self, logged_in_client):
        assert logged_in_client.get("/runs/no-such-run/validate-panel").status_code == 404

    def test_requires_login(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        resp = client.get(f"/runs/{run_id}/validate-panel", follow_redirects=False)
        assert resp.status_code in (303, 401)
        assert "Samples:" not in resp.text

    def test_panel_route_does_not_change_the_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        before = ctx.run_repo.get_by_id(run_id).updated_at
        logged_in_client.get(f"/runs/{run_id}/validate-panel")
        assert ctx.run_repo.get_by_id(run_id).updated_at == before


class TestEditPageWiring:
    """The box on the run page asks for a refresh after changes."""

    def test_edit_page_panel_refreshes_itself(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert 'id="validate-panel"' in page
        assert f'hx-get="/runs/{run_id}/validate-panel"' in page

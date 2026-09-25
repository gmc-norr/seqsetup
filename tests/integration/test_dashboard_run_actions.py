"""Dashboard run actions follow the run state machine and record-keeping rules.

- Archive is offered only where it is allowed (READY -> ARCHIVED); a DRAFT
  cannot be archived, so offering the button there only produced an error.
- An EMPTY draft (no samples) can be deleted by anyone: it can never have
  been Ready, so no sheet from it can have been used. A draft with samples
  may have been Ready and sent back, so it cannot be deleted.
- An ARCHIVED run is the clinical record: only admins may delete it.
"""

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunStatus

HX = {"Origin": "http://testserver", "HX-Request": "true"}


def _make_run(ctx, status=RunStatus.DRAFT, samples=0):
    run = ctx.run_repo.create_run("tester")
    run = ctx.run_repo.get_by_id(run.id)
    run.run_name = "Run"
    for i in range(samples):
        run.add_sample(Sample(sample_id=f"S{i}"))
    run.status = status
    ctx.run_repo.save(run)
    return run.id


def _tab(client, tab):
    resp = client.get(f"/dashboard/tab/{tab}", headers=HX)
    assert resp.status_code == 200
    return resp.text


class TestDashboardButtons:
    """Each row offers only the actions its run may take."""

    def test_draft_row_offers_no_archive(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, samples=1)
        assert f'hx-post="/runs/{run_id}/archive"' not in _tab(logged_in_client, "draft")

    def test_ready_row_offers_archive(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, RunStatus.READY, samples=1)
        assert f'hx-post="/runs/{run_id}/archive"' in _tab(logged_in_client, "ready")

    def test_empty_draft_offers_delete(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        assert f'hx-delete="/runs/{run_id}"' in _tab(logged_in_client, "draft")

    def test_draft_with_samples_offers_no_delete(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, samples=1)
        assert f'hx-delete="/runs/{run_id}"' not in _tab(logged_in_client, "draft")

    def test_archived_delete_shown_to_admin(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, RunStatus.ARCHIVED, samples=1)
        assert f'hx-delete="/runs/{run_id}"' in _tab(logged_in_client, "archived")

    def test_archived_delete_hidden_from_standard_user(self, logged_in_standard_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, RunStatus.ARCHIVED, samples=1)
        assert f'hx-delete="/runs/{run_id}"' not in _tab(logged_in_standard_client, "archived")


class TestDeleteRunRoute:
    """DELETE /runs/{id} enforces the same rules as the buttons."""

    def test_empty_draft_deleted_by_standard_user(self, logged_in_standard_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        resp = logged_in_standard_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run_id) is None

    def test_draft_with_samples_not_deleted(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, samples=1)
        resp = logged_in_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 403
        assert ctx.run_repo.get_by_id(run_id) is not None

    def test_ready_run_not_deleted(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, RunStatus.READY, samples=1)
        resp = logged_in_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 403
        assert ctx.run_repo.get_by_id(run_id) is not None

    def test_archived_run_deleted_by_admin(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, RunStatus.ARCHIVED, samples=1)
        resp = logged_in_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run_id) is None

    def test_archived_run_not_deleted_by_standard_user(self, logged_in_standard_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, RunStatus.ARCHIVED, samples=1)
        resp = logged_in_standard_client.delete(f"/runs/{run_id}", headers=HX)
        assert resp.status_code == 403
        assert ctx.run_repo.get_by_id(run_id) is not None

    @pytest.mark.parametrize("status, tab", [
        (RunStatus.DRAFT, "draft"), (RunStatus.ARCHIVED, "archived"),
    ])
    def test_response_shows_the_tab_the_run_was_on(self, logged_in_client, fresh_app, status, tab):
        _app, ctx, _db = fresh_app
        # Another run stays, so the page shows tabs rather than "No Runs Yet".
        _make_run(ctx, RunStatus.READY, samples=1)
        run_id = _make_run(ctx, status, samples=0 if status == RunStatus.DRAFT else 1)
        resp = logged_in_client.delete(f"/runs/{run_id}", headers=HX)
        # The active tab's button carries the "border-primary" class.
        button = resp.text.split(f'hx-get="/dashboard/tab/{tab}"')[0].rsplit("<button", 1)[1]
        assert "border-primary" in button

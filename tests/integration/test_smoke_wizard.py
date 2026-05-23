"""Smoke tests for the run-creation wizard and run editing.

Covers the core HTMX flows that build up a run from blank to ready:
- GET /runs/new creates a draft and redirects to step 1
- POST /runs/{id}/name updates name (HTMX target)
- POST /runs/{id}/samples adds a sample (HTMX target)
- POST /runs/{id}/instrument switches platform
"""

import pytest


def _origin() -> dict:
    """Same-origin POST header for the CSRF middleware."""
    return {"Origin": "http://testserver"}


def _create_run(logged_in_client) -> str:
    """Create a fresh run via the wizard and return its id."""
    response = logged_in_client.get("/runs/new", follow_redirects=False)
    assert response.status_code == 303, response.text[:300]
    location = response.headers["location"]
    # Format: /runs/new/step/1?run_id=<uuid>
    assert "run_id=" in location
    return location.split("run_id=", 1)[1].split("&", 1)[0]


class TestRunCreation:
    def test_wizard_new_creates_draft_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        before = len(ctx.run_repo.list_all())

        response = logged_in_client.get("/runs/new", follow_redirects=False)
        assert response.status_code == 303

        after = len(ctx.run_repo.list_all())
        assert after == before + 1
        # Newly created run is in DRAFT.
        new_run = ctx.run_repo.list_all()[-1]
        assert new_run.status.value == "draft"

    def test_wizard_step1_renders_for_existing_run(self, logged_in_client):
        run_id = _create_run(logged_in_client)
        response = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}")
        assert response.status_code == 200
        # Some piece of the wizard UI is present.
        body = response.text.lower()
        assert "run" in body and ("name" in body or "instrument" in body)

    def test_wizard_step1_unknown_run_redirects_to_dashboard(self, logged_in_client):
        response = logged_in_client.get(
            "/runs/new/step/1?run_id=nonexistent-id",
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/"


class TestRunEditing:
    def test_update_run_name(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)

        response = logged_in_client.post(
            f"/runs/{run_id}/name",
            data={"run_name": "Smoke Test Run"},
            headers=_origin(),
        )
        assert response.status_code == 200

        updated = ctx.run_repo.get_by_id(run_id)
        assert updated.run_name == "Smoke Test Run"

    def test_update_instrument_changes_platform(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)

        response = logged_in_client.post(
            f"/runs/{run_id}/instrument",
            data={"instrument_platform": "MiSeq i100 Series"},
            headers=_origin(),
        )
        assert response.status_code == 200

        updated = ctx.run_repo.get_by_id(run_id)
        assert updated.instrument_platform.value == "MiSeq i100 Series"


class TestSampleAddition:
    def test_add_sample_to_draft_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)

        response = logged_in_client.post(
            f"/runs/{run_id}/samples",
            data={"sample_id": "S001", "test_id": "WGS"},
            headers=_origin(),
        )
        assert response.status_code == 200

        updated = ctx.run_repo.get_by_id(run_id)
        assert len(updated.samples) == 1
        assert updated.samples[0].sample_id == "S001"
        assert updated.samples[0].test_id == "WGS"

    def test_add_sample_rejects_blank_sample_id(self, logged_in_client):
        run_id = _create_run(logged_in_client)
        response = logged_in_client.post(
            f"/runs/{run_id}/samples",
            data={"sample_id": "", "test_id": "WGS"},
            headers=_origin(),
        )
        assert response.status_code == 400
        assert "required" in response.text.lower()


class TestEditingRequiresDraftStatus:
    """Mutations on a non-DRAFT run are rejected by check_run_editable."""

    def test_cannot_add_sample_to_ready_run(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)

        # Manually flip to READY (bypassing approval gate for this test).
        run = ctx.run_repo.get_by_id(run_id)
        from seqsetup.models.sequencing_run import RunStatus
        run.status = RunStatus.READY
        ctx.run_repo.save(run)

        response = logged_in_client.post(
            f"/runs/{run_id}/samples",
            data={"sample_id": "S001"},
            headers=_origin(),
        )
        assert response.status_code == 403

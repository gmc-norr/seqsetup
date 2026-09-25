"""The Export panel enables downloads for Archived runs, not just Ready.

get_exportable_run already serves /runs/{id}/export/... for READY and
ARCHIVED (exports are pre-generated at Ready and retained through
Ready->Archived). The panel template gated its buttons on Ready only,
leaving an archived run's buttons disabled with the misleading text
"Run must be marked as ready to enable exports" even though the run
already has downloadable, pre-generated content.
"""

from .test_smoke_validation import _make_ready_eligible_run
from seqsetup.services.samplesheet_v1_exporter import SampleSheetV1Exporter


def _origin() -> dict:
    return {"Origin": "http://testserver"}


def _make_archived_run(logged_in_client, ctx, run_id: str) -> str:
    """Build a mark-ready-eligible run, then drive it through the real
    status routes to Ready then Archived, so exports are pre-generated
    the same way production does it."""
    run_id = _make_ready_eligible_run(ctx, run_id)
    resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=_origin())
    assert resp.status_code == 200
    resp = logged_in_client.post(f"/runs/{run_id}/status/archived", headers=_origin())
    assert resp.status_code == 200
    return run_id


class TestArchivedExportPanelEnabled:
    """An archived run's Export panel looks like a Ready run's: links present,
    nothing disabled, no "must be marked as ready" message."""

    def test_archived_panel_has_export_links(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_archived_run(logged_in_client, ctx, "archived-export-run")

        response = logged_in_client.get(f"/runs/{run_id}")
        assert response.status_code == 200
        html = response.text
        panel = html.split('id="export-panel"', 1)[1].split("</fieldset>", 1)[0]

        assert f'href="/runs/{run_id}/export/samplesheet-v2"' in panel
        assert f'href="/runs/{run_id}/export/json"' in panel
        assert f'href="/runs/{run_id}/export/validation-report"' in panel
        assert f'href="/runs/{run_id}/export/validation-pdf"' in panel

        run = ctx.run_repo.get_by_id(run_id)
        if SampleSheetV1Exporter.supports(run.instrument_platform):
            assert f'href="/runs/{run_id}/export/samplesheet-v1"' in panel

        assert 'aria-disabled="true"' not in panel
        assert "Run must be marked as ready" not in panel

    def test_archived_downloads_serve_the_bytes_frozen_at_ready(self, logged_in_client, fresh_app):
        """Pins the guarantee that an archived download serves the exact
        bytes generated at Ready, not a live re-export — this may already
        pass before the panel fix; it documents what the panel now exposes."""
        _app, ctx, _db = fresh_app
        run_id = _make_archived_run(logged_in_client, ctx, "archived-bytes-run")
        run = ctx.run_repo.get_by_id(run_id)

        links_and_stored = [
            ("samplesheet-v2", run.generated_samplesheet_v2),
            ("json", run.generated_json),
            ("validation-report", run.generated_validation_json),
        ]
        if SampleSheetV1Exporter.supports(run.instrument_platform):
            links_and_stored.append(("samplesheet-v1", run.generated_samplesheet_v1))

        for path, stored in links_and_stored:
            assert stored, f"expected {path} to be pre-generated on the archived run"
            resp = logged_in_client.get(f"/runs/{run_id}/export/{path}")
            assert resp.status_code == 200
            assert resp.text == stored

        assert run.generated_validation_pdf
        resp = logged_in_client.get(f"/runs/{run_id}/export/validation-pdf")
        assert resp.status_code == 200
        assert resp.content == run.generated_validation_pdf

    def test_ready_panel_unchanged(self, logged_in_client, fresh_app):
        """A Ready run's panel is unaffected by the fix: same links, none disabled."""
        _app, ctx, _db = fresh_app
        run_id = _make_ready_eligible_run(ctx, "ready-export-run")
        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=_origin())
        assert resp.status_code == 200

        response = logged_in_client.get(f"/runs/{run_id}")
        assert response.status_code == 200
        html = response.text
        panel = html.split('id="export-panel"', 1)[1].split("</fieldset>", 1)[0]

        assert f'href="/runs/{run_id}/export/samplesheet-v2"' in panel
        assert f'href="/runs/{run_id}/export/json"' in panel
        assert f'href="/runs/{run_id}/export/validation-report"' in panel
        assert f'href="/runs/{run_id}/export/validation-pdf"' in panel
        assert 'aria-disabled="true"' not in panel
        assert "Run must be marked as ready" not in panel

    def test_draft_panel_still_shows_waiting_message(self, logged_in_client, fresh_app):
        """A Draft run still shows the waiting message and no export links."""
        _app, ctx, _db = fresh_app
        run_id = _make_ready_eligible_run(ctx, "draft-export-run")

        response = logged_in_client.get(f"/runs/{run_id}")
        assert response.status_code == 200
        html = response.text
        panel = html.split('id="export-panel"', 1)[1].split("</fieldset>", 1)[0]

        assert "Downloads open when the run is Ready." in panel
        assert f'href="/runs/{run_id}/export/samplesheet-v2"' not in panel

"""Sample Sheet follow-ups through the real routes and a real config sync
(spec 2026-09-29 Sample Sheet follow-ups)."""

from .conftest import disable_repos
from .test_sheet_safety import _seed_draft

ORIGIN = {"Origin": "http://testserver"}


class TestInvisibleCharacterStopsMarkReady:
    """A zero-width space in a sample's description keeps the run in Draft,
    with the message (spec §3)."""

    def test_zero_width_space_in_description_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "zw-desc")
        run = ctx.run_repo.get_by_id(run_id)
        run.samples[0].description = "Tube​7"
        ctx.run_repo.save(run)

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert "U+200B" in resp.text
        assert "If you cannot see it, delete the text and type it again." in resp.text
        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.status.value == "draft"
        assert not stored.generated_samplesheet_v2

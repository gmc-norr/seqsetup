"""Sample Sheet safety through the real routes (audit 2026-09 N-10, N-11,
N-12, N-16)."""

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)

from .conftest import disable_repos


ORIGIN = {"Origin": "http://testserver"}


def _seed_draft(ctx, run_id: str, test_id: str = "", run_description: str = "Plan B") -> str:
    """A NovaSeq X DRAFT run with one indexed sample, ready to be marked ready."""
    run = SequencingRun(
        id=run_id,
        run_name="Safety",
        run_description=run_description,
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
    )
    run.add_sample(Sample(
        sample_id="S1",
        test_id=test_id,
        index_pair=IndexPair(
            id="p1", name="p1",
            index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
        ),
    ))
    ctx.run_repo.save(run)
    return run.id


class TestMarkReadyRefusesHiddenCharacters:
    """A hidden character in run or sample text keeps the run in DRAFT."""

    def test_tab_in_run_description_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "hc-desc")
        assert logged_in_client.post(
            f"/runs/{run_id}/name",
            data={"run_name": "Safety", "run_description": "Plan\tB"},
            headers=ORIGIN,
        ).status_code == 200

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#error-banner"
        assert "hidden character" in resp.text
        assert "U+0009" in resp.text
        run = ctx.run_repo.get_by_id(run_id)
        assert run.status.value == "draft"
        assert not run.generated_samplesheet_v2

    def test_nul_in_sample_project_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "hc-project")
        sample_id = ctx.run_repo.get_by_id(run_id).samples[0].id
        assert logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_id}",
            data={"project": "P\x00Q"},
            headers=ORIGIN,
        ).status_code == 200

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#error-banner"
        assert "U+0000" in resp.text
        assert ctx.run_repo.get_by_id(run_id).status.value == "draft"

    def test_visible_text_is_made_ready(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "hc-control", run_description="Åsa's run, 2 × 150")

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert "HX-Retarget" not in resp.headers, resp.text[:400]
        assert ctx.run_repo.get_by_id(run_id).status.value == "ready"

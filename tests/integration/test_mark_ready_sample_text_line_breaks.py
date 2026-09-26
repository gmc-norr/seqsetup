"""Mark Ready refuses a run whose sample text holds a line break.

Drives the real sample-edit route and the real Mark Ready route. Without
the check, a sample name holding a whole fake ``[Data]`` section reached the
frozen Sample Sheet v1 of a READY run, and a sample ID cut to end in a
newline split its v2 row in two.
"""

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)

from .conftest import disable_repos


ORIGIN = {"Origin": "http://testserver"}

FAKE_SECTION = (
    "N\n"
    "[Data]\n"
    "Sample_ID,Sample_Name,Sample_Project,index,index2,Description\n"
    "EVIL,EVIL2,PRJ,GGGGGGGG,CCCCCCCC,junk"
)


def _seed_miseq_draft(ctx, run_id: str) -> tuple[str, str]:
    """A MiSeq DRAFT run (v1 export is supported there) that can be marked
    ready. Returns (run_id, sample.id)."""
    disable_repos(ctx, "test_profile", "app_profile")
    run = SequencingRun(
        id=run_id,
        run_name="LineBreaks",
        instrument_platform=InstrumentPlatform.MISEQ,
        flowcell_type="v3",
        reagent_cycles=600,
        run_cycles=RunCycles(150, 150, 8, 8),
    )
    sample = Sample(
        sample_id="S1",
        sample_name="S1name",
        project="P",
        index_pair=IndexPair(
            id="p1", name="p1",
            index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
        ),
    )
    run.add_sample(sample)
    ctx.run_repo.save(run)
    return run.id, sample.id


class TestMarkReadyRefusesLineBreaks:
    """A line break in sample text keeps the run in DRAFT, with no sheet."""

    def test_sample_name_with_fake_section_is_refused(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id, sample_id = _seed_miseq_draft(ctx, "lb-name")
        assert logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_id}",
            data={"sample_name": FAKE_SECTION},
            headers=ORIGIN,
        ).status_code == 200

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#error-banner"
        assert "line break" in resp.text
        run = ctx.run_repo.get_by_id(run_id)
        assert run.status.value == "draft"
        assert not run.generated_samplesheet_v1

    def test_project_with_line_break_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id, sample_id = _seed_miseq_draft(ctx, "lb-project")
        assert logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_id}",
            data={"project": "P1\r\nP2"},
            headers=ORIGIN,
        ).status_code == 200

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#error-banner"
        assert ctx.run_repo.get_by_id(run_id).status.value == "draft"

    def test_sample_id_clamped_to_end_in_newline_is_refused(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id, sample_id = _seed_miseq_draft(ctx, "lb-id")
        assert logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_id}",
            data={"sample_id": "A" * 255 + "\nEVIL,GGGGGGGG,GGGGGGGG"},
            headers=ORIGIN,
        ).status_code == 200
        stored = ctx.run_repo.get_by_id(run_id).get_sample(sample_id).sample_id
        assert stored == "A" * 255 + "\n", "the route stored a trailing newline"

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#error-banner"
        assert "invalid characters" in resp.text
        run = ctx.run_repo.get_by_id(run_id)
        assert run.status.value == "draft"
        assert not run.generated_samplesheet_v2

    def test_plain_sample_text_is_made_ready_with_one_data_section(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id, sample_id = _seed_miseq_draft(ctx, "lb-control")
        assert logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_id}",
            data={"sample_name": "Tube 2, rack A", "project": "Proj-7"},
            headers=ORIGIN,
        ).status_code == 200

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert "HX-Retarget" not in resp.headers, resp.text[:400]
        assert ctx.run_repo.get_by_id(run_id).status.value == "ready"
        sheet = logged_in_client.get(f"/runs/{run_id}/export/samplesheet-v1").text
        assert sheet.split("\n").count("[Data]") == 1

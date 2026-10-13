"""Mark Ready saves each sheet's target instrument and software with the
sheets, and the API's run list hands it out (the user's request,
2026-10-13). The target must say what the stored sheet really does: each
test reads the i5 the sheet wrote and compares."""

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

from .conftest import disable_repos, mark_ready
from .test_group_1c import _pair
from .test_served_runs import _run, _token

ORIGIN = {"Origin": "http://testserver"}
I5 = "TATAGCCT"
I5_RC = "AGGCTATA"

# (instrument, flow cell, i5 workflow, v2 Index2 column, relies on the
# RunInfo.xml mark, v1 index2 column or None for no v1 sheet)
CASES = [
    (InstrumentPlatform.NOVASEQ_X, "10B", "", "forward", True, None),
    (InstrumentPlatform.NOVASEQ_6000, "S4", "v1.5 reagents", "reverse-complement", False, "reverse-complement"),
    (InstrumentPlatform.NOVASEQ_6000, "S4", "v1.0 reagents", "forward", False, "forward"),
]


def _ready(logged_in_client, ctx, run_id, instrument, flowcell, workflow):
    disable_repos(ctx, "test_profile", "app_profile")
    run = SequencingRun(
        id=run_id, run_name="Target run", instrument_platform=instrument, flowcell_type=flowcell,
        i5_workflow=workflow, run_cycles=RunCycles(151, 151, 10, 10),
    )
    run.add_sample(Sample(sample_id="S1", index_pair=_pair("ATTACTCG", I5, "p1"), lanes=[1]))
    ctx.run_repo.save(run)
    assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200
    stored = ctx.run_repo.get_by_id(run_id)
    assert stored.status == RunStatus.READY, "the run did not reach Ready"
    return stored


def _cell(sheet, section, column):
    """The one data row's ``column`` cell in ``section``."""
    lines = sheet.split(f"{section}\n", 1)[1].split("\n\n", 1)[0].splitlines()
    header, (row,) = lines[0].split(","), lines[1:]
    return row.split(",")[header.index(column)]


def _settings(sheet, section):
    """``section``'s ``key,value`` lines as a dict."""
    lines = sheet.split(f"{section}\n", 1)[1].split("\n\n", 1)[0].splitlines()
    return dict(line.split(",", 1) for line in lines)


def _column(written):
    assert written in (I5, I5_RC), written
    return "forward" if written == I5 else "reverse-complement"


class TestMarkReadySavesTheTargets:
    @pytest.mark.parametrize("instrument,flowcell,workflow,v2_column,needs_mark,v1_column", CASES)
    def test_the_targets_say_what_the_sheets_wrote(
            self, logged_in_client, fresh_app, instrument, flowcell, workflow, v2_column, needs_mark, v1_column):
        _app, ctx, _db = fresh_app
        run = _ready(logged_in_client, ctx, "target-run", instrument, flowcell, workflow)
        v2 = run.sheet_targets["samplesheet_v2"]

        assert _column(_cell(run.generated_samplesheet_v2, "[BCLConvert_Data]", "Index2")) == v2_column
        assert v2 == {
            "instrument": instrument.value,
            "software": "BCL Convert",
            "software_version": _settings(run.generated_samplesheet_v2, "[BCLConvert_Settings]")["SoftwareVersion"],
            "i5_workflow": run.i5_workflow or "Standard",
            "index2_column": v2_column,
            "needs_runinfo_reverse_mark": needs_mark,
        }
        assert v2["software_version"]
        assert ("IndexOrientation,Forward\n" in run.generated_samplesheet_v2) == (v2_column == "forward")

        v1 = run.sheet_targets["samplesheet_v1"]
        if v1_column is None:
            assert run.generated_samplesheet_v1 is None and v1 is None
        else:
            assert _column(_cell(run.generated_samplesheet_v1, "[Data]", "index2")) == v1_column
            assert v1 == {
                "instrument": instrument.value,
                "software": "bcl2fastq",
                "software_version": None,
                "i5_workflow": workflow,
                "index2_column": v1_column,
                "needs_runinfo_reverse_mark": False,
            }

    def test_a_withheld_v1_sheet_has_no_target(self, logged_in_client, fresh_app, monkeypatch):
        from seqsetup.services.samplesheet_v1_exporter import SampleSheetV1Exporter
        _app, ctx, _db = fresh_app
        monkeypatch.setattr(SampleSheetV1Exporter, "withheld", classmethod(
            lambda cls, run, mismatches=None: ("S1 has OverrideCycles a v1 sheet cannot hold", ["S1"])))
        run = _ready(logged_in_client, ctx, "withheld", InstrumentPlatform.NOVASEQ_6000, "S4", "v1.0 reagents")
        assert run.samplesheet_v1_withheld and run.generated_samplesheet_v1 is None
        assert run.sheet_targets["samplesheet_v1"] is None
        assert run.sheet_targets["samplesheet_v2"]["software"] == "BCL Convert"


class TestTheTargetsFollowTheFiles:
    """Kept and cleared exactly like the stored sheets."""

    def test_back_to_draft_clears_them(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "to-draft", InstrumentPlatform.NOVASEQ_X, "10B", "")
        assert logged_in_client.post("/runs/to-draft/status/draft", headers=ORIGIN).status_code == 200
        assert ctx.run_repo.get_by_id("to-draft").sheet_targets == {}

    def test_archiving_keeps_them(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        ready = _ready(logged_in_client, ctx, "to-archive", InstrumentPlatform.NOVASEQ_X, "10B", "")
        assert logged_in_client.post("/runs/to-archive/status/archived", headers=ORIGIN).status_code == 200
        archived = ctx.run_repo.get_by_id("to-archive")
        assert archived.status == RunStatus.ARCHIVED
        assert archived.sheet_targets == ready.sheet_targets != {}

    def test_they_are_not_a_change_in_the_run_history(self):
        from seqsetup.routes.runs import _FINGERPRINT_IGNORED_KEYS
        from seqsetup.services.run_diff import RUN_DIFF_IGNORED_KEYS
        assert "sheet_targets" in _FINGERPRINT_IGNORED_KEYS
        assert "sheet_targets" in RUN_DIFF_IGNORED_KEYS


class TestTheApiHandsThemOut:
    def test_each_run_in_the_list_carries_its_targets(self, logged_in_client, client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _ready(logged_in_client, ctx, "api-target", InstrumentPlatform.NOVASEQ_6000, "S4", "v1.5 reagents")
        api = client.get("/api/runs?status=ready", headers={"Authorization": f"Bearer {_token(ctx)}"})
        (item,) = api.json()["items"]
        assert item["target"] == run.sheet_targets
        assert item["target"]["samplesheet_v1"]["software"] == "bcl2fastq"

    def test_a_run_marked_ready_before_targets_were_saved_has_none(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "older-run")
        api = client.get("/api/runs?status=ready", headers={"Authorization": f"Bearer {_token(ctx)}"})
        (item,) = api.json()["items"]
        assert item["target"] is None

    def test_the_api_schema_describes_the_field(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        schema = client.get("/api/openapi.json", headers={"Authorization": f"Bearer {_token(ctx)}"}).json()
        summary = schema["components"]["schemas"]["RunSummary"]["properties"]["target"]
        assert "Mark Ready" in str(summary)

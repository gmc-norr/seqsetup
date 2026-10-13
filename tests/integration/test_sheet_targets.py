"""Mark Ready saves each sheet's target instrument and software with the
sheets, the API's run list hands it out, and the API Exports page shows it
above each sheet (the user's request, 2026-10-13). The target must say what
the stored sheet really does: each test reads the i5 the sheet wrote and
compares."""

import html
import re

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

from .conftest import disable_repos, mark_ready
from .test_group_1c import _pair
from .test_served_runs import _full, _run, _section, _token

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


RUNINFO_NOTE = ('This sheet relies on BCL Convert acting on the IsReverseComplement="Y" mark '
                "that RunInfo.xml puts on the i5 read.")
NOT_RECORDED = "Not recorded: this run was marked Ready before SeqSetup saved each sheet's target."


def _target_box(section):
    """The section's target rows as {label: value}, or None when it has no box."""
    m = re.search(r'<div class="served-target">(.*?)</div>', section, re.S)
    if not m:
        return None
    assert "<h3" in m.group(1) and "Target instrument and software" in m.group(1)
    return {html.unescape(k): html.unescape(v)
            for k, v in re.findall(r"<dt>(.*?)</dt>\s*<dd>(.*?)</dd>", m.group(1), re.S)}


class TestTheApiExportsPageShowsThem:
    """Above each stored sheet, never above the other files."""

    def test_each_sheet_shows_its_target(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "shown", InstrumentPlatform.NOVASEQ_6000, "S4", "v1.5 reagents")
        page = logged_in_client.get("/served-runs/shown").text

        assert _target_box(_section(page, "samplesheet-v2")) == {
            "Instrument": "NovaSeq 6000",
            "Software": "BCL Convert 4.3.6",
            "i5 workflow": "v1.5 reagents",
            "i5 column": "Reverse complement of the index kit's i5",
        }
        assert _target_box(_section(page, "samplesheet-v1")) == {
            "Instrument": "NovaSeq 6000",
            "Software": "bcl2fastq",
            "i5 workflow": "v1.5 reagents",
            "i5 column": "Reverse complement of the index kit's i5",
        }
        assert RUNINFO_NOTE not in html.unescape(page)
        for resource in ("json", "validation-report", "validation-pdf"):
            section = _section(page, resource)
            assert _target_box(section) is None and NOT_RECORDED not in html.unescape(section)

    def test_a_sheet_that_relies_on_the_runinfo_mark_says_so(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "marked", InstrumentPlatform.NOVASEQ_X, "10B", "")
        section = _section(logged_in_client.get("/served-runs/marked").text, "samplesheet-v2")
        assert _target_box(section)["i5 column"] == "Forward, as the index kit lists it"
        assert RUNINFO_NOTE in html.unescape(section)

    def test_a_v2_sheet_that_states_no_version(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        target = {"instrument": "NovaSeq 6000", "software": "BCL Convert", "software_version": None,
                  "i5_workflow": "v1.0 reagents", "index2_column": "forward", "needs_runinfo_reverse_mark": False}
        run_id = _full(ctx, "no-version", sheet_targets={"samplesheet_v2": target, "samplesheet_v1": None})
        box = _target_box(_section(logged_in_client.get(f"/served-runs/{run_id}").text, "samplesheet-v2"))
        assert box["Software"] == "BCL Convert (the sheet states no version)"

    def test_an_older_run_says_not_recorded(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        page = logged_in_client.get(f"/served-runs/{_full(ctx, 'older')}").text
        for resource in ("samplesheet-v2", "samplesheet-v1"):
            section = _section(page, resource)
            assert _target_box(section) is None
            assert NOT_RECORDED in html.unescape(section), resource

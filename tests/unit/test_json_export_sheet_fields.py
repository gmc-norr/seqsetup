"""The JSON export states, per sample, the i5 and the OverrideCycles the v2
Sample Sheet writes, next to the ones as typed (spec 2026-10-12 batch 2, 2a).
Both come from services/sheet_plan.py, the one place that decides what the
sheet says, so the two exports of one run cannot disagree."""

import json
from pathlib import Path

import pytest

from seqsetup.data.instruments import i5_workflow_names, run_i5_direction
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.json_exporter import JSONExporter
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter

from .test_sheet_plan import _app, _repos, _test

# The baseline: every run of ``_runs()`` exported by the code as it was before
# the two keys were added (ce53b18 plus this batch's spec commit). Regenerate
# with, from the worktree root:
#   PYTHONPATH=src:. python -c 'import json; \
#     from tests.unit.test_json_export_sheet_fields import _runs; \
#     from seqsetup.services.json_exporter import JSONExporter; \
#     print(json.dumps({k: json.loads(JSONExporter.export(r)) \
#       for k, r in _runs().items()}, indent=1))'
# The keys are left in the export's own order, which the tests below check.
BASELINE = Path(__file__).resolve().parents[1] / "fixtures" / "json_export_before_sheet_fields.json"

NEW_KEYS = ("samplesheet_index2", "samplesheet_override_cycles")

I7, I5, I5_RC = "ATTACTCG", "TATAGCCT", "AGGCTATA"
# An 8-base index on a 10-cycle read, so the Index 2 mask is asymmetric.
CYCLES = RunCycles(151, 151, 10, 10)
MASK, MASK_REVERSED = "Y151;I8N2;I8N2;Y151", "Y151;I8N2;N2I8;Y151"

# Every instrument and workflow of the shipped instruments file.
PAIRS = [(platform.value, workflow)
         for platform in InstrumentPlatform
         for workflow in (i5_workflow_names(platform.value) or [])]
PAIR_IDS = [f"{name}|{workflow}" for name, workflow in PAIRS]


def _run(instrument, workflow="", i7=I7, i5=I5) -> SequencingRun:
    """One dual-index sample on ``instrument``, with its own name and project.
    ``i7=None`` leaves the sample without any index; ``i5=None`` leaves it with
    an i7 only."""
    sample = Sample(id="s1", sample_id="S1", sample_name="One", project="ProjectA",
                    description="a sample", test_id="WGS", test_version="1", lanes=[1])
    if i7 and i5:
        sample.index_pair = IndexPair(
            id="p1", name="p1",
            index1=Index(name="i7", sequence=i7, index_type=IndexType.I7),
            index2=Index(name="i5", sequence=i5, index_type=IndexType.I5),
        )
    elif i7:
        sample.assign_index1(Index(name="i7", sequence=i7, index_type=IndexType.I7))
    return SequencingRun(
        id="json-sheet-run", run_name="JSON-sheet", run_description="batch 2 item 2a",
        instrument_platform=InstrumentPlatform(instrument), i5_workflow=workflow,
        created_by="tester", run_cycles=CYCLES, samples=[sample],
    )


def _runs() -> dict:
    """The runs the baseline fixture holds, one per i5 state and one per
    missing index. Keep in step with the fixture."""
    return {
        "index2-column-reversed": _run("NextSeq 500/550"),
        "index2-mask-reversed": _run("NovaSeq X Series"),
        "i5-read-forward": _run("MiSeq"),
        "no-i5": _run("NextSeq 500/550", i5=None),
        "no-index": _run("NovaSeq X Series", i7=None, i5=None),
    }


def _profiles():
    """A BCLConvert profile with an Index2 and an OverrideCycles column, so the
    sheet has a cell to compare each new key against."""
    return _repos([_app("BCLConvertJson")], [_test("WGS", ("BCLConvertJson", "1.0.0"))])


def _data_row(run) -> dict:
    """The run's one [BCLConvert_Data] row, as column -> cell."""
    test_repo, app_repo = _profiles()
    lines = SampleSheetV2Exporter.export(run, test_repo, app_repo).splitlines()
    start = lines.index("[BCLConvert_Data]")
    return dict(zip(lines[start + 1].split(","), lines[start + 2].split(",")))


def _sample_json(run) -> dict:
    return json.loads(JSONExporter.export(run))["samples"][0]


def _unsettled(run) -> SequencingRun:
    """``run`` with an i5 workflow its instrument does not have — the way
    ``i5_direction`` refuses to answer that a test can reach."""
    run.i5_workflow = "No such workflow"
    return run


class TestTheSheetsValuesAreInTheJSON:
    """Each new key holds what the sheet's cell holds."""

    @pytest.mark.parametrize("instrument,workflow", PAIRS, ids=PAIR_IDS)
    def test_the_i5_is_the_sheets_index2_cell(self, instrument, workflow):
        run = _run(instrument, workflow)
        assert _sample_json(run)["samplesheet_index2"] == _data_row(run)["Index2"]

    @pytest.mark.parametrize("instrument,workflow", PAIRS, ids=PAIR_IDS)
    def test_the_override_cycles_is_the_sheets_cell(self, instrument, workflow):
        run = _run(instrument, workflow)
        assert (_sample_json(run)["samplesheet_override_cycles"]
                == _data_row(run)["OverrideCycles"])

    @pytest.mark.parametrize("instrument,workflow", PAIRS, ids=PAIR_IDS)
    def test_the_keys_as_typed_are_still_as_typed(self, instrument, workflow):
        sample = _sample_json(_run(instrument, workflow))
        assert sample["index2"]["sequence"] == I5
        assert sample["override_cycles"] == MASK

    def test_an_instrument_that_reverses_the_index2_column(self):
        sample = _sample_json(_run("NextSeq 500/550"))
        assert run_i5_direction(_run("NextSeq 500/550")).index2_column_reversed is True
        assert sample["index2"]["sequence"] == I5
        assert sample["samplesheet_index2"] == I5_RC
        assert sample["override_cycles"] == MASK
        assert sample["samplesheet_override_cycles"] == MASK

    def test_an_instrument_that_reverses_the_index2_mask(self):
        sample = _sample_json(_run("NovaSeq X Series"))
        assert run_i5_direction(_run("NovaSeq X Series")).index2_mask_reversed is True
        assert sample["index2"]["sequence"] == I5
        assert sample["samplesheet_index2"] == I5
        assert sample["override_cycles"] == MASK
        assert sample["samplesheet_override_cycles"] == MASK_REVERSED

    def test_an_instrument_that_reads_the_i5_forward(self):
        sample = _sample_json(_run("MiSeq"))
        assert sample["samplesheet_index2"] == sample["index2"]["sequence"] == I5
        assert sample["samplesheet_override_cycles"] == sample["override_cycles"] == MASK

    def test_a_sample_without_an_i5(self):
        run = _run("NextSeq 500/550", i5=None)
        sample = _sample_json(run)
        assert sample["index2"] is None
        assert sample["samplesheet_index2"] is None
        assert _data_row(run)["Index2"] == ""

    def test_a_sample_without_any_index(self):
        run = _run("NovaSeq X Series", i7=None, i5=None)
        sample = _sample_json(run)
        assert sample["override_cycles"] is None
        assert sample["samplesheet_override_cycles"] is None
        assert sample["samplesheet_index2"] is None
        assert _data_row(run)["OverrideCycles"] == ""

    def test_an_instrument_with_no_i5_direction_leaves_both_null(self):
        """SeqSetup cannot say what a sheet would write for a run whose i5
        direction it cannot answer -- and no Sample Sheet can be written for
        that run either. The JSON export still states everything else."""
        sample = _sample_json(_unsettled(_run("NovaSeq X Series")))
        assert sample["samplesheet_index2"] is None
        assert sample["samplesheet_override_cycles"] is None
        assert sample["index2"]["sequence"] == I5
        assert sample["override_cycles"] == MASK


class TestEveryOldKeyIsUnchanged:
    """The two keys are added; nothing else about the export moves."""

    def test_the_export_is_the_old_one_plus_the_two_new_keys(self):
        baseline = json.loads(BASELINE.read_text())
        runs = _runs()
        assert sorted(baseline) == sorted(runs)
        for label, run in runs.items():
            data = json.loads(JSONExporter.export(run))
            for sample in data["samples"]:
                for key in NEW_KEYS:
                    assert key in sample, f"{label}: {key} missing"
                    del sample[key]
            assert data == baseline[label], label

    def test_the_old_keys_keep_their_order(self):
        baseline = json.loads(BASELINE.read_text())
        for label, run in _runs().items():
            data = json.loads(JSONExporter.export(run))
            assert list(data) == list(baseline[label]), label
            for sample, was in zip(data["samples"], baseline[label]["samples"]):
                assert [key for key in sample if key not in NEW_KEYS] == list(was), label

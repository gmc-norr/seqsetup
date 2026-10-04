"""The i5 rule (spec 2026-10-04 group A2, §2 and §4): from how the run's
workflow reads the i5 and whether RunInfo.xml marks a reversed read, the
sheets write the Index2 column, the Index 2 part of OverrideCycles and the
header line, and the checks read the i5 the way the instrument does."""

from datetime import datetime

import pytest

from seqsetup.data.instruments import NoI5Direction, i5_direction, run_i5_direction
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.models.validation import ValidationResult
from seqsetup.services.samplesheet_v1_exporter import SampleSheetV1Exporter
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter
from seqsetup.services.validation import ValidationService
from seqsetup.services.validation_report import ValidationReportJSON, ValidationReportPDF

F, R = "forward", "reverse-complement"
I7, I5, I5_RC = "ATTACTCG", "TATAGCCT", "AGGCTATA"
I7_10, I5_10, I5_10_RC = "ATTACTCGAA", "TATAGCCTGG", "CCAGGCTATA"

# (instrument, workflow, how it reads the i5, Index2 column reversed, Index 2 mask reversed)
RULE = [
    ("NovaSeq X Series", "Standard", R, False, True),
    ("NextSeq 1000/2000", "Standard", R, False, True),
    ("MiSeq i100 Series", "Index-first", F, False, False),
    ("MiSeq i100 Series", "Read-first", R, False, True),
    ("NextSeq 500/550", "Standard", R, True, False),
    ("MiniSeq", "Standard kits", R, True, False),
    ("MiniSeq", "Rapid kits", F, False, False),
    ("NovaSeq 6000", "v1.5 reagents", R, True, False),
    ("NovaSeq 6000", "v1.0 reagents", F, False, False),
    ("HiSeq 4000", "Standard", R, True, False),
    ("HiSeq X", "Standard", R, True, False),
    ("MiSeq", "Standard", F, False, False),
    ("HiSeq 2000/2500", "Standard", F, False, False),
    ("GAIIx", "Standard", F, False, False),
]
RULE_IDS = [f"{name}|{workflow}" for name, workflow, *_ in RULE]


def _run(instrument: str, workflow: str = "", i7: str = I7, i5: str = I5,
         cycles: RunCycles = None, status: RunStatus = RunStatus.DRAFT) -> SequencingRun:
    return SequencingRun(
        id="a2-sheet-run", run_name="A2-sheet", instrument_platform=InstrumentPlatform(instrument),
        created_by="tester", created_at=datetime(2026, 10, 4, 12, 0, 0),
        run_cycles=cycles or RunCycles(151, 151, 10, 10), i5_workflow=workflow, status=status,
        samples=[Sample(id="s1", sample_id="S1", sample_name="S1", lanes=[1], index_pair=IndexPair(
            id="p1", name="p1",
            index1=Index(name="i7", sequence=i7, index_type=IndexType.I7),
            index2=Index(name="i5", sequence=i5, index_type=IndexType.I5),
        ))],
    )


def _line(sheet: str, start: str) -> str:
    (line,) = [line for line in sheet.splitlines() if line.startswith(start)]
    return line


class TestTheRule:
    """Two facts give the read direction, the Index2 column and the mask."""

    @pytest.mark.parametrize("instrument,workflow,read,column,mask", RULE, ids=RULE_IDS)
    def test_each_built_in_workflow(self, instrument, workflow, read, column, mask):
        direction = i5_direction(instrument, workflow)
        assert direction.workflow == workflow
        assert direction.read_orientation == read
        assert direction.index2_column_reversed is column
        assert direction.index2_mask_reversed is mask

    def test_no_workflow_is_the_standard_one(self):
        assert i5_direction("MiSeq i100 Series", "").workflow == "Index-first"
        assert i5_direction("MiniSeq", "").workflow == "Standard kits"

    def test_a_run_uses_its_own_workflow(self):
        assert run_i5_direction(_run("MiSeq i100 Series", "Read-first")).read_orientation == R


class TestTheSheets:
    """What the v2 and v1 sheets write, for an 8-base i5 on a 10-cycle read
    (I8N2) and a 10-base one (I10, symmetric)."""

    @pytest.mark.parametrize("instrument,workflow,read,column,mask", RULE, ids=RULE_IDS)
    def test_the_v2_sheet(self, instrument, workflow, read, column, mask):
        sheet = SampleSheetV2Exporter.export(_run(instrument, workflow))
        assert _line(sheet, "1,S1,") == f"1,S1,{I7},{I5_RC if column else I5},1,1"
        index2_mask = "N2I8" if mask else "I8N2"
        assert _line(sheet, "OverrideCycles,") == f"OverrideCycles,Y151;I8N2;{index2_mask};Y151"
        assert ("IndexOrientation,Forward" in sheet.splitlines()) is not column
        # Cloud_Data names the library with the i5 as the kit lists it.
        assert _line(sheet, "S1,A2-sheet,") == f"S1,A2-sheet,S1_{I7}_{I5}"

    @pytest.mark.parametrize("instrument,workflow,read,column,mask", RULE, ids=RULE_IDS)
    def test_a_symmetric_mask_does_not_change(self, instrument, workflow, read, column, mask):
        sheet = SampleSheetV2Exporter.export(_run(instrument, workflow, i7=I7_10, i5=I5_10))
        assert _line(sheet, "OverrideCycles,") == "OverrideCycles,Y151;I10;I10;Y151"
        assert _line(sheet, "1,S1,") == f"1,S1,{I7_10},{I5_10_RC if column else I5_10},1,1"

    @pytest.mark.parametrize("instrument,workflow,read", [
        ("MiSeq", "Standard", F),
        ("NovaSeq 6000", "v1.5 reagents", R),
        ("NovaSeq 6000", "v1.0 reagents", F),
    ])
    def test_the_v1_sheet_writes_the_i5_as_read(self, instrument, workflow, read):
        sheet = SampleSheetV1Exporter.export(_run(instrument, workflow))
        i5 = I5_RC if read == R else I5
        assert _line(sheet, "1,S1,") == f"1,S1,S1,,{I7},{i5},"


# Today's sheets (main 9f14e32), for _run(instrument) with an 8-base or a
# 10-base i5. They differ between instruments only in the values in TODAY.
TODAY_V2 = """\
[Header]
FileFormatVersion,2
RunName,A2-sheet
InstrumentPlatform,{platform}
IndexOrientation,Forward
Custom_UUID,a2-sheet-run

[Reads]
Read1Cycles,151
Read2Cycles,151
Index1Cycles,10
Index2Cycles,10

[BCLConvert_Settings]
SoftwareVersion,4.3.6
FastqCompressionFormat,gzip
NoLaneSplitting,false
CreateFastqForIndexReads,0
OverrideCycles,Y151;{index1};{index2};Y151

[BCLConvert_Data]
Lane,Sample_ID,Index,Index2,BarcodeMismatchesIndex1,BarcodeMismatchesIndex2
1,S1,{i7},{i5_cell},1,1

[Cloud_Settings]
GeneratedVersion,2.7.0

[Cloud_Data]
Sample_ID,ProjectName,LibraryName
S1,A2-sheet,S1_{i7}_{i5}

"""
TODAY_V1 = """\
[Header]
IEMFileVersion,4
Investigator Name,tester
Experiment Name,A2-sheet
Date,2026-10-04
Workflow,GenerateFASTQ
Application,FASTQ Only
Chemistry,Default
Custom_UUID,a2-sheet-run

[Reads]
151
151

[Settings]
ReverseComplement,0
BarcodeMismatchesIndex1,1
BarcodeMismatchesIndex2,1

[Data]
Lane,Sample_ID,Sample_Name,Sample_Project,index,index2,Description
1,S1,S1,,{i7},{i5_cell},

"""
# instrument: (InstrumentPlatform line, i5 written reversed today)
TODAY = {
    "NovaSeq X Series": ("NovaSeqXSeries", False),
    "MiSeq i100 Series": ("MiSeqi100Series", False),
    "NextSeq 1000/2000": ("NextSeq1k2k", False),
    "NextSeq 500/550": ("NextSeq500", True),
    "MiniSeq": ("MiniSeq", True),
    "NovaSeq 6000": ("NovaSeq6000", True),
    "GAIIx": ("GAIIx", False),
    "HiSeq 2000/2500": ("HiSeq2500", False),
    "HiSeq 4000": ("HiSeq4000", True),
    "HiSeq X": ("HiSeqX", True),
    "MiSeq": ("MiSeq", False),
}
# The differences this change makes, by design (spec §4).
HEADER_LINE_GONE = {"NextSeq 500/550", "MiniSeq", "NovaSeq 6000", "HiSeq 4000", "HiSeq X"}
INDEX2_MASK_NOW = {  # an 8-base i5: today's mask -> the new one
    "NovaSeq X Series": ("I8N2", "N2I8"),
    "NextSeq 1000/2000": ("I8N2", "N2I8"),
    "NextSeq 500/550": ("N2I8", "I8N2"),
    "MiniSeq": ("N2I8", "I8N2"),
    "NovaSeq 6000": ("N2I8", "I8N2"),
    "HiSeq 4000": ("N2I8", "I8N2"),
    "HiSeq X": ("N2I8", "I8N2"),
}


def today_sheet(instrument: str, size: int, version: int = 2) -> str:
    """Today's v2 (or v1) sheet of _run(instrument) with an 8- or 10-base i5."""
    platform, reversed_i5 = TODAY[instrument]
    i7, i5, i5_rc = (I7, I5, I5_RC) if size == 8 else (I7_10, I5_10, I5_10_RC)
    if version == 1:
        return TODAY_V1.format(i7=i7, i5_cell=i5_rc if reversed_i5 else i5)
    if size == 8:
        index1, index2 = "I8N2", (INDEX2_MASK_NOW.get(instrument, ("I8N2",))[0])
    else:
        index1 = index2 = "I10"
    return TODAY_V2.format(platform=platform, index1=index1, index2=index2, i7=i7, i5=i5,
                           i5_cell=i5_rc if reversed_i5 else i5)


class TestTodaysSheets:
    """With each built-in instrument's standard workflow, the sheets are
    today's apart from the named differences (spec §4)."""

    @pytest.mark.parametrize("size", [8, 10])
    @pytest.mark.parametrize("instrument", sorted(TODAY))
    def test_the_v2_sheet(self, instrument, size):
        expected = today_sheet(instrument, size)
        if instrument in HEADER_LINE_GONE:
            expected = expected.replace("IndexOrientation,Forward\n", "")
        if size == 8 and instrument in INDEX2_MASK_NOW:
            old, new = INDEX2_MASK_NOW[instrument]
            expected = expected.replace(f"OverrideCycles,Y151;I8N2;{old};Y151",
                                        f"OverrideCycles,Y151;I8N2;{new};Y151")
        i7, i5 = (I7, I5) if size == 8 else (I7_10, I5_10)
        assert SampleSheetV2Exporter.export(_run(instrument, i7=i7, i5=i5)) == expected

    @pytest.mark.parametrize("size", [8, 10])
    @pytest.mark.parametrize("instrument", ["MiSeq", "NovaSeq 6000"])
    def test_the_v1_sheet_does_not_change(self, instrument, size):
        i7, i5 = (I7, I5) if size == 8 else (I7_10, I5_10)
        assert SampleSheetV1Exporter.export(_run(instrument, i7=i7, i5=i5)) == today_sheet(
            instrument, size, version=1)


class TestNoDirection:
    """A workflow the instrument does not list, or an instrument with no
    settings, gives no direction: an error, never a guess."""

    def test_an_unlisted_workflow(self):
        with pytest.raises(NoI5Direction) as exc:
            i5_direction("MiSeq i100 Series", "Old name")
        assert str(exc.value) == (
            "Old name is not an i5 workflow of MiSeq i100 Series "
            "(it has: Index-first, Read-first)."
        )

    def test_the_name_must_match_exactly(self):
        with pytest.raises(NoI5Direction):
            i5_direction("MiSeq i100 Series", "read-first")

    def test_an_instrument_with_no_settings(self):
        with pytest.raises(NoI5Direction) as exc:
            i5_direction("No Such Sequencer", "")
        assert str(exc.value) == "No Such Sequencer is not in the local instruments file."

    def test_no_direction_is_a_value_error(self):
        assert issubclass(NoI5Direction, ValueError)

    def test_the_writers_refuse_it(self):
        run = _run("MiSeq i100 Series", "Old name")
        with pytest.raises(NoI5Direction):
            SampleSheetV2Exporter.export(run)
        with pytest.raises(NoI5Direction):
            SampleSheetV1Exporter.export(_run("MiSeq", "Old name"))


DARK_ONLY_REVERSED = "ATCGATCC"  # read reversed it starts GG: dark on two-colour instruments


def _dark_errors(instrument: str, workflow: str) -> list:
    run = _run(instrument, workflow, i7="ACGTACGT", i5=DARK_ONLY_REVERSED)
    return [e for e in ValidationService.validate_run(run).dark_cycle_errors if e.index_type == "i5"]


class TestTheChecks:
    """The dark-start check reads the i5 the way the run's workflow does."""

    @pytest.mark.parametrize("instrument,workflow", [
        ("NextSeq 500/550", "Standard"),
        ("NextSeq 1000/2000", "Standard"),
        ("MiniSeq", "Standard kits"),
        ("MiSeq i100 Series", "Read-first"),
        ("NovaSeq 6000", "v1.5 reagents"),
        ("NovaSeq X Series", "Standard"),
    ])
    def test_an_i5_dark_when_read_reversed_is_refused(self, instrument, workflow):
        assert len(_dark_errors(instrument, workflow)) == 1

    @pytest.mark.parametrize("instrument,workflow", [
        ("MiniSeq", "Rapid kits"),
        ("MiSeq i100 Series", "Index-first"),
        ("NovaSeq 6000", "v1.0 reagents"),
    ])
    def test_it_passes_when_read_forward(self, instrument, workflow):
        assert _dark_errors(instrument, workflow) == []

    def test_the_colour_balance_reads_it_the_same_way(self):
        run = _run("MiniSeq", "Standard kits", i7="ACGTACGT", i5=DARK_ONLY_REVERSED)
        balance = ValidationService.validate_run(run).color_balance[1].i5_balance
        rapid = _run("MiniSeq", "Rapid kits", i7="ACGTACGT", i5=DARK_ONLY_REVERSED)
        rapid_balance = ValidationService.validate_run(rapid).color_balance[1].i5_balance
        # The first cycle: G read reversed (standard kits), A read forward (Rapid).
        assert (balance.positions[0].g_count, balance.positions[0].a_count) == (1, 0)
        assert (rapid_balance.positions[0].g_count, rapid_balance.positions[0].a_count) == (0, 1)


def _errors(run, category: str) -> list:
    return [e for e in ValidationService.validate_configuration(run) if e.category == category]


class TestNoDirectionStopsMarkReady:
    """Validation reports a run with no direction and skips the checks that
    need one."""

    def test_an_unlisted_workflow_on_a_draft(self):
        (error,) = _errors(_run("MiSeq i100 Series", "Old name"), "no_i5_direction")
        assert error.message == (
            "Old name is not an i5 workflow of MiSeq i100 Series "
            "(it has: Index-first, Read-first). Pick one in Run Setup."
        )

    def test_an_unlisted_workflow_on_a_ready_run(self):
        run = _run("MiSeq i100 Series", "Old name", status=RunStatus.READY)
        (error,) = _errors(run, "no_i5_direction")
        assert error.message == (
            "Old name is not an i5 workflow of MiSeq i100 Series "
            "(it has: Index-first, Read-first)."
        )

    def test_the_checks_that_need_a_direction_do_not_run(self):
        run = _run("MiSeq i100 Series", "Old name", i7="ACGTACGT", i5=DARK_ONLY_REVERSED)
        result = ValidationService.validate_run(run)
        assert result.error_count >= 1
        assert result.dark_cycle_errors == []
        assert result.color_balance == {}

    def test_a_listed_workflow_gives_no_error(self):
        assert _errors(_run("MiSeq i100 Series", "Read-first"), "no_i5_direction") == []


class TestTheResultNamesTheDirection:
    """Validation stores the workflow and read direction it used, and the
    report prints them, or why there is none (spec §3)."""

    def test_the_result_carries_them(self):
        result = ValidationService.validate_run(_run("MiSeq i100 Series", "Read-first"))
        assert (result.i5_workflow, result.i5_read_orientation, result.no_i5_direction) == (
            "Read-first", R, "")

    def test_a_run_from_before_names_the_standard_one(self):
        result = ValidationService.validate_run(_run("MiSeq i100 Series"))
        assert (result.i5_workflow, result.i5_read_orientation) == ("Index-first", F)

    def test_none_with_the_reason(self):
        result = ValidationService.validate_run(_run("MiSeq i100 Series", "Old name"))
        assert (result.i5_workflow, result.i5_read_orientation) == ("", "")
        assert result.no_i5_direction == (
            "Old name is not an i5 workflow of MiSeq i100 Series "
            "(it has: Index-first, Read-first)."
        )

    def test_the_json_report(self):
        run = _run("MiSeq i100 Series", "Read-first")
        report = ValidationReportJSON._build_report(run, ValidationService.validate_run(run))
        assert (report["i5_workflow"], report["i5_read_orientation"]) == ("Read-first", R)

    def test_the_json_report_with_none(self):
        run = _run("MiSeq i100 Series", "Old name")
        report = ValidationReportJSON._build_report(run, ValidationService.validate_run(run))
        reason = ("none (Old name is not an i5 workflow of MiSeq i100 Series "
                  "(it has: Index-first, Read-first).)")
        assert (report["i5_workflow"], report["i5_read_orientation"]) == (reason, reason)

    def test_the_pdf_report(self):
        run = _run("MiSeq i100 Series", "Read-first")
        rows = ValidationReportPDF._run_info(run, ValidationService.validate_run(run))
        assert ["i5 workflow", "Read-first"] in rows
        assert ["i5 read direction", R] in rows
        assert rows.index(["i5 workflow", "Read-first"]) == rows.index(["Flowcell", "—"]) + 1

    def test_a_result_built_elsewhere_reads_none(self):
        result = ValidationResult(duplicate_sample_ids=[], index_collisions=[], distance_matrices={})
        report = ValidationReportJSON._build_report(_run("MiSeq"), result)
        assert (report["i5_workflow"], report["i5_read_orientation"]) == ("none", "none")

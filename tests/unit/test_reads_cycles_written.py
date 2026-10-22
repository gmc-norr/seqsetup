"""Each cycle count reaches its own line of the sheet ("Risk 4" gap).

Every test of the [Reads] section used Read 1 = Read 2 and Index 1 = Index 2
(151/151/10/10), so a writer that swapped Read1Cycles and Read2Cycles, or
Index1Cycles and Index2Cycles, passed them all. These runs have four
different counts: the v2 [Reads] section (profile path, as Mark Ready writes
it, and the fallback), the v1 [Reads] section, and the JSON export's cycle
fields must each carry every count under its own name. A single-end run
(Read 2 = 0) and a single-index run (Index 2 = 0) pin what is written today:
v2 writes the zero line (``Read2Cycles,0`` / ``Index2Cycles,0``) rather than
leaving it out. Whether the instruments accept a zero line is not known here
and belongs to the lab's validation; if leaving the line out turns out to be
right, change those tests with the writer.
"""

from ..sheet_through_profiles import sheet as _sheet

import json
from datetime import datetime

import pytest
import yaml

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.models.test_profile import TestProfile as _TestProfile
from seqsetup.services.json_exporter import JSONExporter
from seqsetup.services.samplesheet_v1_exporter import SampleSheetV1Exporter
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter

from .test_sheet_plan import SHIPPED, _repos, _wgs
from .test_writer_uses_the_plan import _section, _shipped

# (Read 1, Read 2, Index 1, Index 2): no two alike, so a swap of any two
# shows. The second set is the first with each pair swapped, so a writer
# cannot pass by writing the same counts for every run.
DISTINCT = [
    pytest.param((151, 101, 10, 8), id="151-101-10-8"),
    pytest.param((101, 151, 8, 10), id="101-151-8-10"),
]

# Index sequences as long as each index read, so OverrideCycles reads the
# whole index.
_I7 = {8: "ACGTACGT", 10: "ACGTACGTAC"}
_I5 = {8: "TTGGCCAA", 10: "TTGGCCAATT"}


def _sample(sample_id: str, index1: int, index2: int, test="WGS") -> Sample:
    sample = Sample(id=f"id-{sample_id}", sample_id=sample_id, test_id=test,
                    test_version="1", lanes=[1])
    i7 = Index(name=f"{sample_id}7", sequence=_I7[index1], index_type=IndexType.I7)
    if index2:
        sample.index_pair = IndexPair(
            id=f"p{sample_id}", name=f"p{sample_id}", index1=i7,
            index2=Index(name=f"{sample_id}5", sequence=_I5[index2], index_type=IndexType.I5))
    else:
        sample.assign_index1(i7)
    return sample


def _run(counts, platform=InstrumentPlatform.NOVASEQ_X, flowcell="10B") -> SequencingRun:
    read1, read2, index1, index2 = counts
    return SequencingRun(
        id="reads-run", run_name="Reads", instrument_platform=platform,
        flowcell_type=flowcell, created_by="tester", created_at=datetime(2026, 10, 15, 9, 0),
        run_cycles=RunCycles(read1, read2, index1, index2),
        samples=[_sample("S1", index1, index2)],
    )


def _shipped_repos():
    """The shipped WGS test and its application profiles, as a lab syncs them."""
    apps = [_shipped(f.name) for f in
            sorted((SHIPPED / "application_profiles" / "dragen").glob("*.yaml"))]
    wgs = _TestProfile.from_yaml(
        yaml.safe_load((SHIPPED / "test_profiles" / "Wgs.yaml").read_text()), "Wgs.yaml")
    return _repos(apps, [wgs])


def _v2_reads(sheet: str) -> list[str]:
    return _section(sheet, "Reads")


def _v1_reads(sheet: str) -> list[str]:
    return sheet.split("[Reads]\n", 1)[1].split("\n\n", 1)[0].splitlines()


def _expected_v2(counts) -> list[str]:
    read1, read2, index1, index2 = counts
    return [f"Read1Cycles,{read1}", f"Read2Cycles,{read2}",
            f"Index1Cycles,{index1}", f"Index2Cycles,{index2}"]


class TestTheV2ReadsSectionWritesEachCountOnItsOwnLine:
    """[Reads] names each count and writes it once, in the order Read 1,
    Read 2, Index 1, Index 2, on both writer paths."""

    @pytest.mark.parametrize("counts", DISTINCT)
    def test_the_profile_path_with_the_shipped_profiles_writes_the_four_counts(self, counts):
        # The path Mark Ready takes: _pregenerate_exports passes the profile repos.
        sheet = SampleSheetV2Exporter.export(_run(counts), *_shipped_repos())

        assert "[DragenGermline_Settings]" in sheet  # only the profile path writes it
        assert _v2_reads(sheet) == _expected_v2(counts)

    @pytest.mark.parametrize("counts", DISTINCT)
    def test_the_profile_path_with_test_profiles_writes_the_four_counts(self, counts):
        apps, tests = _wgs()
        sheet = SampleSheetV2Exporter.export(_run(counts), *_repos(apps, tests))

        assert "[DragenGermline_Settings]" in sheet
        assert _v2_reads(sheet) == _expected_v2(counts)

    @pytest.mark.parametrize("counts", DISTINCT)
    def test_the_fallback_path_writes_the_four_counts(self, counts):
        sheet = _sheet(_run(counts))

        assert "[BCLConvert_Data]" in sheet
        assert "[DragenGermline_Settings]" not in sheet  # no profiles: the fallback ran
        assert _v2_reads(sheet) == _expected_v2(counts)

    def test_each_label_appears_once_in_the_sheet(self):
        sheet = SampleSheetV2Exporter.export(_run((151, 101, 10, 8)), *_shipped_repos())

        for label in ("Read1Cycles,", "Read2Cycles,", "Index1Cycles,", "Index2Cycles,"):
            assert sum(line.startswith(label) for line in sheet.splitlines()) == 1, label


class TestTheV1ReadsSectionKeepsReadOneFirst:
    """v1 [Reads] holds the bare read lengths, Read 1 then Read 2; IEM sheets
    carry no index counts there."""

    @pytest.mark.parametrize("counts", DISTINCT)
    def test_read_one_then_read_two(self, counts):
        run = _run(counts, platform=InstrumentPlatform.NOVASEQ_6000, flowcell="S4")

        assert _v1_reads(SampleSheetV1Exporter.export(run)) == [str(counts[0]), str(counts[1])]

    def test_the_index_counts_are_not_written_as_reads(self):
        run = _run((151, 101, 10, 8), platform=InstrumentPlatform.NOVASEQ_6000, flowcell="S4")

        reads = _v1_reads(SampleSheetV1Exporter.export(run))

        assert "10" not in reads and "8" not in reads


class TestTheJsonExportNamesEachCount:
    """The JSON export's ``cycles`` carries each count under its own key."""

    @pytest.mark.parametrize("counts", DISTINCT)
    def test_the_four_counts_under_their_keys(self, counts):
        read1, read2, index1, index2 = counts

        cycles = json.loads(JSONExporter.export(_run(counts)))["cycles"]

        assert cycles == {"read1_cycles": read1, "read2_cycles": read2,
                          "index1_cycles": index1, "index2_cycles": index2,
                          "total_cycles": read1 + read2 + index1 + index2}

    def test_a_run_without_cycles_has_none(self):
        run = _run((151, 101, 10, 8))
        run.run_cycles = None

        assert json.loads(JSONExporter.export(run))["cycles"] is None


class TestASingleEndRunToday:
    """Read 2 = 0. Pins what is written today: v2 writes ``Read2Cycles,0``
    (the line is not left out), v1 writes Read 1 alone, the JSON says 0."""

    COUNTS = (151, 0, 10, 8)

    def test_v2_writes_read2cycles_zero_on_the_profile_path(self):
        sheet = SampleSheetV2Exporter.export(_run(self.COUNTS), *_shipped_repos())
        assert _v2_reads(sheet) == ["Read1Cycles,151", "Read2Cycles,0",
                                    "Index1Cycles,10", "Index2Cycles,8"]

    def test_v2_writes_read2cycles_zero_on_the_fallback_path(self):
        sheet = _sheet(_run(self.COUNTS))
        assert _v2_reads(sheet) == ["Read1Cycles,151", "Read2Cycles,0",
                                    "Index1Cycles,10", "Index2Cycles,8"]

    def test_v1_writes_read_one_alone(self):
        run = _run(self.COUNTS, platform=InstrumentPlatform.NOVASEQ_6000, flowcell="S4")
        assert _v1_reads(SampleSheetV1Exporter.export(run)) == ["151"]

    def test_the_json_says_zero(self):
        cycles = json.loads(JSONExporter.export(_run(self.COUNTS)))["cycles"]
        assert (cycles["read1_cycles"], cycles["read2_cycles"]) == (151, 0)


class TestASingleIndexRunToday:
    """Index 2 = 0, the sample has an i7 only. Pins what is written today:
    v2 writes ``Index2Cycles,0``, v1 writes both reads, the JSON says 0."""

    COUNTS = (151, 101, 10, 0)

    def test_v2_writes_index2cycles_zero_on_the_profile_path(self):
        sheet = SampleSheetV2Exporter.export(_run(self.COUNTS), *_shipped_repos())
        assert _v2_reads(sheet) == ["Read1Cycles,151", "Read2Cycles,101",
                                    "Index1Cycles,10", "Index2Cycles,0"]

    def test_v2_writes_index2cycles_zero_on_the_fallback_path(self):
        sheet = _sheet(_run(self.COUNTS))
        assert _v2_reads(sheet) == ["Read1Cycles,151", "Read2Cycles,101",
                                    "Index1Cycles,10", "Index2Cycles,0"]

    def test_v1_writes_both_reads(self):
        run = _run(self.COUNTS, platform=InstrumentPlatform.NOVASEQ_6000, flowcell="S4")
        assert _v1_reads(SampleSheetV1Exporter.export(run)) == ["151", "101"]

    def test_the_json_says_zero(self):
        cycles = json.loads(JSONExporter.export(_run(self.COUNTS)))["cycles"]
        assert (cycles["index1_cycles"], cycles["index2_cycles"]) == (10, 0)

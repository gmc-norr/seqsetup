"""The run-wide OverrideCycles: the JSON export's global_override_cycles and the
OverrideCycles line of the fallback Sample Sheet (no application profiles).

It is given only when every sample gets that same value in its own row: the
sample's stored OverrideCycles (one typed by hand, too), else the calculated
one. A sample with an OverrideCycles of its own keeps it.

10-cycle indexes on 10 index cycles mask nothing, so no instrument changes the
Index 2 part and the values below are written as they are."""

import json

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.cycle_calculator import CycleCalculator
from seqsetup.services.json_exporter import JSONExporter
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter

CALCULATED = "Y151;I10;I10;Y151"
TYPED = "Y151;I10;I10;U10Y141"
_INDEXES = {1: ("ATTACTCGAT", "TATAGCCTAG"), 2: ("TCCGGAGACT", "ATAGAGGCTC"),
            3: ("CGCTCATTGA", "GGCTCTGAAC")}


def _sample(n: int, override_cycles=None, i7=None) -> Sample:
    seq7, seq5 = _INDEXES[n]
    return Sample(
        sample_id=f"S{n}", sample_name=f"S{n}",
        index_pair=IndexPair(
            id=f"p{n}", name=f"p{n}",
            index1=Index(name=f"i7-{n}", sequence=i7 or seq7, index_type=IndexType.I7),
            index2=Index(name=f"i5-{n}", sequence=seq5, index_type=IndexType.I5),
        ),
        override_cycles=override_cycles,
    )


def _run(*samples: Sample) -> SequencingRun:
    return SequencingRun(
        id="shared-oc-run", run_name="SharedOC", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        run_cycles=RunCycles(151, 151, 10, 10), samples=list(samples),
    )


def _section(sheet: str, name: str) -> list[str]:
    lines = sheet.split("\n")
    start = lines.index(f"[{name}]") + 1
    return lines[start:lines.index("", start)]


class TestTheSharedValue:
    """CycleCalculator.infer_global_override_cycles."""

    def test_samples_with_no_value_of_their_own_share_the_calculated_one(self):
        assert CycleCalculator.infer_global_override_cycles(_run(_sample(1), _sample(2))) == CALCULATED

    def test_samples_that_hold_the_calculated_value_share_it(self):
        run = _run(_sample(1, CALCULATED), _sample(2, CALCULATED))
        assert CycleCalculator.infer_global_override_cycles(run) == CALCULATED

    def test_a_stored_value_with_commas_is_the_same_value(self):
        run = _run(_sample(1, "Y151,I10,I10,Y151"), _sample(2))
        assert CycleCalculator.infer_global_override_cycles(run) == CALCULATED

    def test_one_sample_with_a_typed_value_means_no_shared_value(self):
        run = _run(_sample(1), _sample(2, TYPED), _sample(3))
        assert CycleCalculator.infer_global_override_cycles(run) is None

    def test_a_typed_value_every_sample_holds_is_shared(self):
        run = _run(_sample(1, TYPED), _sample(2, TYPED))
        assert CycleCalculator.infer_global_override_cycles(run) == TYPED

    def test_different_index_lengths_still_mean_no_shared_value(self):
        run = _run(_sample(1, TYPED), _sample(2, TYPED, i7="TCCGGAGA"))
        assert CycleCalculator.infer_global_override_cycles(run) is None


class TestTheFallbackSampleSheet:
    """SampleSheetV2Exporter.export without application profiles."""

    def test_a_typed_value_is_written_in_its_samples_row(self):
        sheet = SampleSheetV2Exporter.export(_run(_sample(1), _sample(2, TYPED)))

        assert not any(line.startswith("OverrideCycles,") for line in _section(sheet, "BCLConvert_Settings"))
        header, *rows = _section(sheet, "BCLConvert_Data")
        column = header.split(",").index("OverrideCycles")
        assert [(row.split(",")[0], row.split(",")[column]) for row in rows] == [
            ("S1", CALCULATED), ("S2", TYPED)]

    def test_a_typed_value_every_sample_holds_is_written_once(self):
        sheet = SampleSheetV2Exporter.export(_run(_sample(1, TYPED), _sample(2, TYPED)))

        assert f"OverrideCycles,{TYPED}" in _section(sheet, "BCLConvert_Settings")
        assert "OverrideCycles" not in _section(sheet, "BCLConvert_Data")[0]

    def test_without_typed_values_the_calculated_value_is_written_once(self):
        sheet = SampleSheetV2Exporter.export(_run(_sample(1), _sample(2)))

        assert f"OverrideCycles,{CALCULATED}" in _section(sheet, "BCLConvert_Settings")
        assert "OverrideCycles" not in _section(sheet, "BCLConvert_Data")[0]


class TestTheJsonExport:
    """JSONExporter: global_override_cycles agrees with the samples' own values."""

    def test_the_global_value_is_null_when_a_sample_has_a_typed_value(self):
        data = json.loads(JSONExporter.export(_run(_sample(1), _sample(2, TYPED))))

        assert data["bclconvert_settings"]["global_override_cycles"] is None
        assert [s["override_cycles"] for s in data["samples"]] == [CALCULATED, TYPED]

    def test_the_global_value_is_the_typed_value_every_sample_holds(self):
        data = json.loads(JSONExporter.export(_run(_sample(1, TYPED), _sample(2, TYPED))))

        assert data["bclconvert_settings"]["global_override_cycles"] == TYPED

    def test_without_typed_values_the_global_value_is_the_calculated_one(self):
        data = json.loads(JSONExporter.export(_run(_sample(1), _sample(2))))

        assert data["bclconvert_settings"]["global_override_cycles"] == CALCULATED

"""Two ways around the i5 rule are closed, and one case it cannot settle is
refused (spec 2026-10-04 group A2, §2): a typed Index 2 part that masks cycles
before the index, a BCL Convert profile whose Settings would change how BCL
Convert reads the i5, and an i5 used shorter than it is stored inside a longer
Index 2 read where the i5 is read reversed."""

import pytest

from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.cycle_calculator import INDEX2_ORDER_RULE, CycleCalculator
from seqsetup.services.profile_validator import (
    ProfileValidationError,
    validate_application_profile_yaml,
)
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter
from seqsetup.services.sheet_text import I5_RULE_SETTINGS
from seqsetup.services.validation import ValidationService

RC = RunCycles(151, 151, 10, 10)


class TestTheIndex2Order:
    """A stored OverrideCycles is in reading order: in the Index 2 part, the
    index comes before any masked or UMI cycles."""

    def test_the_message(self):
        assert INDEX2_ORDER_RULE == (
            "Index 2 in OverrideCycles is written in reading order in SeqSetup: the index "
            "first, then the masked cycles (for example I8N2). SeqSetup writes it the way "
            "the instrument needs."
        )

    @pytest.mark.parametrize("value", [
        "Y151;I8N2;N2I8;Y151", "Y151;I8N2;U2I8;Y151", "Y151;I10;N1I8N1;Y151",
        "y151;i8n2;n2i8;y151", "Y151,I8N2,N2I8,Y151",
    ])
    def test_cycles_masked_before_the_index_are_refused(self, value):
        assert CycleCalculator.override_cycles_problem(value, RC) == "index2_order"

    @pytest.mark.parametrize("value", [
        "Y151;I8N2;I8N2;Y151", "Y151;I10;I10;Y151", "Y151;I8N2;N10;Y151",
        "Y151;I8U2;I8N2;Y151",
    ])
    def test_the_index_first_or_no_index_is_fine(self, value):
        assert CycleCalculator.override_cycles_problem(value, RC) is None

    def test_a_single_end_run(self):
        rc = RunCycles(151, 0, 10, 10)
        assert CycleCalculator.override_cycles_problem("Y151;I10;N2I8", rc) == "index2_order"
        assert CycleCalculator.override_cycles_problem("Y151;I10;I8N2", rc) is None

    def test_a_run_without_index_2(self):
        rc = RunCycles(151, 151, 10, 0)
        assert CycleCalculator.override_cycles_problem("Y151;I8N2;Y151", rc) is None

    def test_a_mismatch_is_reported_first(self):
        assert CycleCalculator.override_cycles_problem("Y151;I8N2;N2I8", RC) == "mismatch"


def _profile(settings: dict, app_name: str = "BCLConvert") -> dict:
    return {
        "ApplicationProfileName": "Guard",
        "ApplicationProfileVersion": "1.0.0",
        "ApplicationName": app_name,
        "ApplicationType": "BclConvert",
        "Settings": settings,
        "Data": {"OverrideCycles": ""},
        "DataFields": ["Sample_ID", "Index", "Index2", "OverrideCycles"],
    }


class TestProfilesCannotChangeTheRule:
    """A BCL Convert profile's Settings may not carry the four settings that
    change how BCL Convert reads the i5; OverrideCycles as a data column stays."""

    def test_the_four_settings(self):
        assert I5_RULE_SETTINGS == (
            "OverrideCycles", "OverrideReads",
            "RunInfoIndex2ReverseComplement", "Index2ColumnReverseComplement",
        )

    @pytest.mark.parametrize("key", list(I5_RULE_SETTINGS) + ["overridecycles"])
    def test_the_sync_refuses_it(self, key):
        with pytest.raises(ProfileValidationError) as exc:
            validate_application_profile_yaml(_profile({key: "1"}), "Guard.yaml")
        assert (
            f"Field 'Settings' may not set {key!r} in the BCLConvert profile: SeqSetup "
            f"writes the i5 and OverrideCycles itself"
        ) in str(exc.value)

    def test_another_application_may_carry_it(self):
        validate_application_profile_yaml(_profile({"OverrideCycles": "1"}, "DragenGermline"))

    def test_overridecycles_as_a_data_column_is_fine(self):
        validate_application_profile_yaml(_profile({"SoftwareVersion": "4.3.6"}))

    @pytest.mark.parametrize("key", list(I5_RULE_SETTINGS))
    def test_the_writer_refuses_a_stored_one(self, key):
        profile = ApplicationProfile.from_yaml(_profile({"SoftwareVersion": "4.3.6"}), "Guard.yaml")
        profile.settings[key] = "1"
        run = _run()
        with pytest.raises(ValueError, match=f"may not set {key}"):
            SampleSheetV2Exporter._write_application_profile_section(
                _Out(), profile, run.samples, run)


class _Out:
    def write(self, text):
        pass


def _run(platform=InstrumentPlatform.NOVASEQ_X, override: str = "") -> SequencingRun:
    return SequencingRun(
        instrument_platform=platform, run_cycles=RC,
        samples=[Sample(sample_id="S1", override_cycles=override or None, index_pair=IndexPair(
            id="p1", name="p1",
            index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
        ))],
    )


class TestATypedValueIsWrittenForTheReader:
    """A typed I8N2 is in reading order, so it is written N2I8 where BCL
    Convert reverses it back (NovaSeq X), and as typed elsewhere."""

    @pytest.mark.parametrize("platform,written", [
        (InstrumentPlatform.NOVASEQ_X, "Y151;I8N2;N2I8;Y151"),
        (InstrumentPlatform.NEXTSEQ_500_550, "Y151;I8N2;I8N2;Y151"),
    ])
    def test_the_profile_data_column(self, platform, written):
        from io import StringIO
        profile = ApplicationProfile.from_yaml(_profile({"SoftwareVersion": "4.3.6"}), "Guard.yaml")
        run = _run(platform, override="Y151;I8N2;I8N2;Y151")
        out = StringIO()
        SampleSheetV2Exporter._write_application_profile_section(out, profile, run.samples, run)
        assert out.getvalue().splitlines()[-2].endswith(f",{written}")


SHORTENED = "i5_shortened_on_reversed_read"


def _shortened(instrument: str, workflow: str = "", i5: str = "ACGGTTCAAG", index2_cycles=8,
               override: str = "", cycles: RunCycles = RC) -> SequencingRun:
    return SequencingRun(
        id="a2-short-i5", instrument_platform=InstrumentPlatform(instrument), i5_workflow=workflow,
        run_cycles=cycles,
        samples=[Sample(sample_id="S1", index2_cycles=index2_cycles, override_cycles=override or None,
                        index_pair=IndexPair(
                            id="p1", name="p1",
                            index1=Index(name="i7", sequence="ATTACTCGAT", index_type=IndexType.I7),
                            index2=Index(name="i5", sequence=i5, index_type=IndexType.I5),
                        ))],
    )


def _shortened_errors(run: SequencingRun) -> list:
    return [e for e in ValidationService.validate_configuration(run) if e.category == SHORTENED]


class TestAShortenedI5OnAReversedRead:
    """An i5 used shorter than it is stored, inside a longer Index 2 read, is
    refused where the i5 is read reversed: which of its bases BCL Convert
    compares is not settled. A kit's i5 cycles reach the sample as its
    index2_cycles, so the sample's setting covers both."""

    def test_the_message(self):
        (error,) = _shortened_errors(_shortened("NovaSeq X Series"))
        assert error.message == (
            "1 sample(s) use fewer i5 cycles than their i5 has, inside a longer Index 2 read: "
            "S1. NovaSeq X Series (Standard) reads the i5 reversed, so which i5 bases BCL "
            "Convert compares is not settled. Use all of the i5's cycles, or make the Index 2 "
            "read as long as the cycles used."
        )
        assert error.sample_names == ["S1"]
        assert error.severity.value == "error"

    @pytest.mark.parametrize("instrument,workflow", [
        ("NovaSeq X Series", ""), ("NextSeq 500/550", ""), ("MiSeq i100 Series", "Read-first"),
    ])
    def test_it_is_refused_where_the_i5_is_read_reversed(self, instrument, workflow):
        assert len(_shortened_errors(_shortened(instrument, workflow))) == 1

    def test_a_typed_value_is_refused_too(self):
        run = _shortened("NovaSeq X Series", index2_cycles=None, override="Y151;I10;I8N2;Y151")
        assert len(_shortened_errors(run)) == 1

    @pytest.mark.parametrize("instrument,workflow", [
        ("MiSeq", ""), ("MiSeq i100 Series", "Index-first"),
    ])
    def test_it_passes_where_the_i5_is_read_forward(self, instrument, workflow):
        assert _shortened_errors(_shortened(instrument, workflow)) == []

    def test_a_long_i5_on_a_short_read_passes(self):
        # No masked cycles: not changed here (spec, Not in this change).
        run = _shortened("NovaSeq X Series", index2_cycles=None, cycles=RunCycles(151, 151, 8, 8))
        assert _shortened_errors(run) == []

    def test_a_short_i5_on_a_long_read_passes(self):
        assert _shortened_errors(_shortened("NovaSeq X Series", i5="TATAGCCT", index2_cycles=None)) == []

    def test_the_whole_i5_passes(self):
        assert _shortened_errors(_shortened("NovaSeq X Series", index2_cycles=None)) == []
        assert _shortened_errors(_shortened("NovaSeq X Series", index2_cycles=10)) == []

    def test_a_run_with_no_direction_reports_only_that(self):
        run = _shortened("MiSeq i100 Series", "Old name")
        categories = [e.category for e in ValidationService.validate_configuration(run)]
        assert "no_i5_direction" in categories
        assert SHORTENED not in categories

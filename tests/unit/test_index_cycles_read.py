"""The checks count the index bases read from the sample's OverrideCycles,
and an index must have exactly as many bases as the cycles read for it
(spec 2026-10-05 group A3, §4). Illumina, DRAGEN v4.3 BCL conversion: "Length
of string must match number of first index cycles in RunInfo.xml or number
specified in OverrideCycles." """

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.validation import ValidationService, clear_validation_cache
from seqsetup.services.validation_utils import effective_index_read_length, index_cycles_read

LENGTH = "index_length_differs_from_override_cycles"
RC = RunCycles(151, 151, 10, 10)


def _sample(sample_id: str = "S1", i7: str = "ACGTACGTAC", i5: str | None = "TTGGCCAATT",
            override: str | None = None, i7_cycles=None, i5_cycles=None, lanes=(1,)) -> Sample:
    sample = Sample(sample_id=sample_id, lanes=list(lanes), override_cycles=override)
    if i5 is None:
        sample.assign_index1(Index(name=f"{sample_id}-i7", sequence=i7, index_type=IndexType.I7))
    else:
        sample.index_pair = IndexPair(
            id=f"p-{sample_id}", name=f"p-{sample_id}",
            index1=Index(name=f"{sample_id}-i7", sequence=i7, index_type=IndexType.I7),
            index2=Index(name=f"{sample_id}-i5", sequence=i5, index_type=IndexType.I5),
        )
    if i7_cycles is not None:
        sample.index1_cycles = i7_cycles
    if i5_cycles is not None:
        sample.index2_cycles = i5_cycles
    return sample


def _run(*samples: Sample, cycles: RunCycles = RC,
         platform=InstrumentPlatform.NOVASEQ_X) -> SequencingRun:
    flowcell = {InstrumentPlatform.NOVASEQ_X: "10B", InstrumentPlatform.MISEQ: "v3"}[platform]
    return SequencingRun(run_name="A3", instrument_platform=platform, flowcell_type=flowcell,
                         run_cycles=cycles, samples=list(samples))


def _categories(run: SequencingRun) -> list[str]:
    return [e.category for e in ValidationService.validate_configuration(run)
            if e.severity.value == "error"]


def _length_errors(run: SequencingRun) -> list:
    return [e for e in ValidationService.validate_configuration(run) if e.category == LENGTH]


class TestTheBasesRead:
    """The I cycles of the index read's part of the sample's OverrideCycles,
    typed, else computed."""

    def test_a_typed_value_wins_over_the_kit(self):
        sample = _sample(override="Y151;I10;I10;Y151", i7_cycles=6)
        run = _run(sample)
        assert index_cycles_read(sample, 1, run) == 10
        assert effective_index_read_length(sample, 1, run) == 10

    @pytest.mark.parametrize("i7,i7_cycles,cycles,today", [
        ("ACGTACGTAC", None, 10, 10),     # plain
        ("ACGTACGT", None, 10, 8),        # shorter index
        ("ACGTACGTAC", 8, 10, 8),         # kit cycles
        ("ACGTACGTACGT", None, 10, 10),   # longer than the read
    ])
    def test_without_a_typed_value_it_is_todays_number(self, i7, i7_cycles, cycles, today):
        sample = _sample(i7=i7, i5=None, i7_cycles=i7_cycles)
        run = _run(sample, cycles=RunCycles(151, 151, cycles, 0))
        assert index_cycles_read(sample, 1, run) == today
        assert effective_index_read_length(sample, 1, run) == today

    def test_a_sample_without_that_index_reads_none_of_it(self):
        sample = _sample(i5=None)
        assert index_cycles_read(sample, 2, _run(sample)) == 0

    def test_an_override_cycles_that_does_not_fit_gives_none(self):
        sample = _sample(override="Y151;I8;I10;Y151")
        run = _run(sample)
        assert index_cycles_read(sample, 1, run) is None
        assert effective_index_read_length(sample, 1, run) == 10   # today's number

    def test_a_run_without_that_read_gives_none(self):
        sample = _sample(i5=None)
        assert index_cycles_read(sample, 2, _run(sample, cycles=RunCycles(151, 151, 10, 0))) is None

    def test_an_unindexed_sample_without_a_typed_value_gives_none(self):
        sample = Sample(sample_id="S1", lanes=[1])
        assert index_cycles_read(sample, 1, _run(sample)) is None


class TestTheReviewCases:
    """The spec review's case: a typed I10 over kit index cycles 6 reads all
    10 bases, so two i7s equal in their first 6 are not a duplicate."""

    def test_kit_cycles_6_with_a_typed_i10(self):
        a = _sample("A", i7="ACGTACGTAA", i5=None, override="Y151;I10;Y151", i7_cycles=6)
        b = _sample("B", i7="ACGTACCCGG", i5=None, override="Y151;I10;Y151", i7_cycles=6)
        c = _sample("C", i7="TTTTGGGGCC", i5=None)
        for s in (a, b, c):
            s.barcode_mismatches_index1 = 0
        run = _run(a, b, c, cycles=RunCycles(151, 151, 10, 0))
        clear_validation_cache()
        result = ValidationService.validate_run(run)
        assert result.index_collisions == []
        categories = [e.category for e in result.configuration_errors]
        assert "duplicate_index_pair" not in categories
        assert "index_length_mismatch" not in categories
        assert LENGTH not in categories


class TestTheLengthRule:
    """Mark Ready refuses an index whose length differs from the cycles its
    OverrideCycles reads for it."""

    def test_the_message(self):
        run = _run(_sample("S1", i7_cycles=8))
        (error,) = _length_errors(run)
        assert error.message == (
            "1 sample(s) have an index whose length differs from the index cycles their "
            "OverrideCycles reads: S1 (i7: 10 bases, 8 read). BCL Convert needs each index to "
            "have as many bases as the cycles read for it. Use an index of that length, or "
            "change the OverrideCycles or the kit's index cycles."
        )
        assert error.sample_names == ["S1"]
        assert error.severity.value == "error"

    def test_both_indexes_and_more_than_five_samples(self):
        samples = [_sample(f"S{n}", i7_cycles=8, i5_cycles=8) for n in range(1, 7)]
        (error,) = _length_errors(_run(*samples))
        assert error.message.startswith(
            "6 sample(s) have an index whose length differs from the index cycles their "
            "OverrideCycles reads: S1 (i7: 10 bases, 8 read), S1 (i5: 10 bases, 8 read), "
            "S2 (i7: 10 bases, 8 read), S2 (i5: 10 bases, 8 read), S3 (i7: 10 bases, 8 read), "
            "and 7 more. "
        )
        assert error.sample_names == [f"S{n}" for n in range(1, 7)]

    @pytest.mark.parametrize("platform", [InstrumentPlatform.NOVASEQ_X, InstrumentPlatform.MISEQ])
    @pytest.mark.parametrize("fields", [
        pytest.param(dict(i7_cycles=8), id="kit-cycles-fewer"),
        pytest.param(dict(override="Y151;I6N4;I10;Y151"), id="typed-fewer"),
        pytest.param(dict(i7="ACGTACGT", override="Y151;I10;I10;Y151"), id="typed-more"),
        pytest.param(dict(override="Y151;N10;I10;Y151"), id="typed-none"),
        pytest.param(dict(i5=None, override="Y151;I10;I10;Y151"), id="cycles-for-a-missing-index"),
    ])
    def test_it_is_refused(self, platform, fields):
        assert len(_length_errors(_run(_sample(**fields), platform=platform))) == 1

    @pytest.mark.parametrize("fields", [
        pytest.param(dict(i5="TTGGCCAA", i7_cycles=8), id="i7"),
        pytest.param(dict(i7="ACGTACGT", i5_cycles=8), id="i5"),
    ])
    def test_kit_cycles_8_on_an_8_cycle_read(self, fields):
        # The later-list case: 0 errors before this change.
        run = _run(_sample(**fields), cycles=RunCycles(151, 151, 8, 8))
        assert _categories(run) == [LENGTH]

    def test_a_12_base_i5_used_as_8_on_a_10_cycle_read(self):
        run = _run(_sample(i5="TTGGCCAATTGG", i5_cycles=8))
        assert _categories(run) == [LENGTH]

    @pytest.mark.parametrize("fields", [
        pytest.param(dict(), id="plain"),
        pytest.param(dict(i7="ACGTACGT", i5="TTGGCCAA"), id="shorter-index-masked-after"),
        pytest.param(dict(override="Y151;I10;I10;Y151"), id="typed-full"),
        pytest.param(dict(i5=None), id="single-index"),
        pytest.param(dict(i7_cycles=10, i5_cycles=10), id="kit-cycles-equal"),
    ])
    def test_it_passes(self, fields):
        assert _length_errors(_run(_sample(**fields))) == []

    def test_an_index_longer_than_its_read_is_reported_once(self):
        run = _run(_sample(i7="ACGTACGTACGT"))
        assert _categories(run) == ["index_exceeds_cycles"]

    def test_a_malformed_kit_read_pattern_is_reported_once(self):
        # 'U8YY*' quietly becomes U8Y143, so the calculated OverrideCycles
        # fits the run; only the OverrideCycles check reports the sample.
        sample = _sample(i7_cycles=8)
        sample.read1_override_pattern = "U8YY*"
        assert _categories(_run(sample)) == ["override_cycles_invalid"]

    def test_an_override_cycles_that_does_not_fit_is_reported_once(self):
        run = _run(_sample(override="Y151;I8;I10;Y151"))
        assert _categories(run) == ["override_cycles_mismatch"]


class TestIndexExceedsCyclesRespectsATypedValue:
    """A typed OverrideCycles that fits the run decides the cycles the
    index_exceeds_cycles check compares, not the kit's index cycles."""

    def test_a_typed_value_that_fits(self):
        sample = _sample(i7="ACGTACGT", i5="TTGGCCAA", override="Y151;I8N2;I8N2;Y151",
                         i7_cycles=12, i5_cycles=12)
        assert _categories(_run(sample)) == []

    def test_without_the_typed_value_both_are_still_refused(self):
        sample = _sample(i7="ACGTACGT", i5="TTGGCCAA", i7_cycles=12, i5_cycles=12)
        assert _categories(_run(sample)) == ["index_exceeds_cycles", "index_exceeds_cycles"]

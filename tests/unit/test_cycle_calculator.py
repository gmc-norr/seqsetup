"""Tests for cycle calculator service."""

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunCycles, SequencingRun
from seqsetup.services.cycle_calculator import CycleCalculator


class TestCycleCalculator:
    """Tests for CycleCalculator."""

    def test_calculate_run_cycles_default(self):
        """Test default cycle calculation for 300-cycle kit."""
        cycles = CycleCalculator.calculate_run_cycles(300)
        assert cycles.read1_cycles == 151
        assert cycles.read2_cycles == 151
        assert cycles.index1_cycles == 10
        assert cycles.index2_cycles == 10

    def test_calculate_run_cycles_with_overrides(self):
        """Test cycle calculation with custom values."""
        cycles = CycleCalculator.calculate_run_cycles(
            300, read1_cycles=100, index1_cycles=8
        )
        assert cycles.read1_cycles == 100
        assert cycles.read2_cycles == 151  # Default
        assert cycles.index1_cycles == 8
        assert cycles.index2_cycles == 10  # Default

    def test_override_cycles_matching_length(self, sample_run_cycles):
        """Test override cycles when index length matches run cycles."""
        sample = Sample(
            sample_id="test",
            index_pair=IndexPair(
                id="test",
                name="test",
                index1=Index(name="i7", sequence="ATCGATCGAT", index_type=IndexType.I7),
                index2=Index(name="i5", sequence="GCTAGCTACC", index_type=IndexType.I5),
            ),
        )

        override = CycleCalculator.calculate_override_cycles(sample, sample_run_cycles)
        assert override == "Y151;I10;I10;Y151"

    def test_override_cycles_shorter_index(self, sample_run_cycles):
        """Test override cycles when index is shorter than run cycles."""
        sample = Sample(
            sample_id="test",
            index_pair=IndexPair(
                id="test",
                name="test",
                index1=Index(name="i7", sequence="ATCGATCG", index_type=IndexType.I7),
                index2=Index(name="i5", sequence="GCTAGCTA", index_type=IndexType.I5),
            ),
        )

        override = CycleCalculator.calculate_override_cycles(sample, sample_run_cycles)
        assert override == "Y151;I8N2;I8N2;Y151"

    def test_override_cycles_no_index2(self, sample_run_cycles):
        """Test override cycles with single indexing (no i5)."""
        sample = Sample(
            sample_id="test",
            index_pair=IndexPair(
                id="test",
                name="test",
                index1=Index(name="i7", sequence="ATCGATCGAT", index_type=IndexType.I7),
                index2=None,
            ),
        )

        override = CycleCalculator.calculate_override_cycles(sample, sample_run_cycles)
        assert override == "Y151;I10;N10;Y151"

    def test_override_cycles_no_index(self, sample_run_cycles):
        """Test override cycles when sample has no index assigned."""
        sample = Sample(sample_id="test")

        override = CycleCalculator.calculate_override_cycles(sample, sample_run_cycles)
        assert override == "Y151;N10;N10;Y151"

    def test_override_cycles_longer_index(self):
        """Test override cycles when index is longer than run cycles."""
        run_cycles = RunCycles(
            read1_cycles=151, read2_cycles=151, index1_cycles=8, index2_cycles=8
        )
        sample = Sample(
            sample_id="test",
            index_pair=IndexPair(
                id="test",
                name="test",
                index1=Index(name="i7", sequence="ATCGATCGAT", index_type=IndexType.I7),  # 10bp
                index2=Index(name="i5", sequence="GCTAGCTACC", index_type=IndexType.I5),  # 10bp
            ),
        )

        override = CycleCalculator.calculate_override_cycles(sample, run_cycles)
        # Should only use available cycles
        assert override == "Y151;I8;I8;Y151"

    def test_single_end_run_has_no_read2_segment(self):
        # BCL Convert needs one segment per read in RunInfo.xml; a read with
        # 0 cycles is not in RunInfo, so a 'Y0' segment makes the sheet invalid.
        run_cycles = RunCycles(read1_cycles=151, read2_cycles=0, index1_cycles=10, index2_cycles=10)
        sample = Sample(
            sample_id="test",
            index_pair=IndexPair(
                id="test",
                name="test",
                index1=Index(name="i7", sequence="ATCGATCGAT", index_type=IndexType.I7),
                index2=Index(name="i5", sequence="GCTAGCTACC", index_type=IndexType.I5),
            ),
        )
        assert CycleCalculator.calculate_override_cycles(sample, run_cycles) == "Y151;I10;I10"

    def test_infer_global_without_samples_skips_zero_cycle_reads(self):
        run = SequencingRun(run_cycles=RunCycles(151, 0, 10, 0))
        assert CycleCalculator.infer_global_override_cycles(run) == "Y151;I10"

    def test_infer_global_override_same_lengths(self, sample_run):
        """Test inferring global override when all indexes have same length."""
        global_override = CycleCalculator.infer_global_override_cycles(sample_run)
        # All samples have 8bp indexes with 10 cycle config
        assert global_override == "Y151;I8N2;I8N2;Y151"

    def test_infer_global_override_mixed_lengths(self, sample_run):
        """Test that global override returns None with mixed index lengths."""
        # Add a sample with different index lengths
        sample_run.add_sample(
            Sample(
                sample_id="Different",
                index_pair=IndexPair(
                    id="diff",
                    name="diff",
                    index1=Index(
                        name="i7", sequence="ATCGATCGATCG", index_type=IndexType.I7
                    ),  # 12bp
                    index2=Index(
                        name="i5", sequence="GCTAGCTACCGG", index_type=IndexType.I5
                    ),  # 12bp
                ),
            )
        )

        global_override = CycleCalculator.infer_global_override_cycles(sample_run)
        assert global_override is None


class TestReverseOverrideSegment:
    """Tests for CycleCalculator.reverse_override_segment()."""

    def test_single_token_unchanged(self):
        """Single token should remain the same."""
        assert CycleCalculator.reverse_override_segment("I10") == "I10"

    def test_two_tokens_reversed(self):
        """Two tokens should be reversed."""
        assert CycleCalculator.reverse_override_segment("I8N2") == "N2I8"

    def test_three_tokens_reversed(self):
        """Three tokens should be reversed."""
        assert CycleCalculator.reverse_override_segment("N2I8N2") == "N2I8N2"

    def test_mask_only(self):
        """Mask-only segment."""
        assert CycleCalculator.reverse_override_segment("N10") == "N10"

    def test_umi_and_index(self):
        """UMI combined with index tokens."""
        assert CycleCalculator.reverse_override_segment("U4I6") == "I6U4"

    def test_empty_string(self):
        """Empty string should return empty."""
        assert CycleCalculator.reverse_override_segment("") == ""

    def test_case_insensitive(self):
        """Should handle lowercase input."""
        assert CycleCalculator.reverse_override_segment("i8n2") == "N2I8"

    def test_wildcard_token_preserved(self):
        """A '*' token must survive the reversal, not be silently dropped — on
        an RC instrument a dropped Index2 token corrupts demultiplexing."""
        assert CycleCalculator.reverse_override_segment("I4N*") == "N*I4"
        assert CycleCalculator.reverse_override_segment("N*I4") == "I4N*"


class TestBuildReadSegment:
    """Tests for CycleCalculator._build_read_segment() — directly shapes the
    Read1/Read2 OverrideCycles tokens emitted to the sequencer."""

    def test_none_pattern_reads_all(self):
        assert CycleCalculator._build_read_segment(151, None) == "Y151"

    def test_empty_pattern_reads_all(self):
        assert CycleCalculator._build_read_segment(151, "") == "Y151"

    def test_wildcard_only(self):
        assert CycleCalculator._build_read_segment(151, "Y*") == "Y151"

    def test_leading_mask_wildcard(self):
        assert CycleCalculator._build_read_segment(151, "N2Y*") == "N2Y149"

    def test_umi_then_read(self):
        assert CycleCalculator._build_read_segment(151, "U8Y*") == "U8Y143"

    def test_mask_read_mask(self):
        assert CycleCalculator._build_read_segment(151, "N2Y*N3") == "N2Y146N3"

    def test_trailing_mask(self):
        assert CycleCalculator._build_read_segment(151, "Y*N2") == "Y149N2"


class TestExpandOverrideCycles:
    """Tests for CycleCalculator.expand_override_cycles().

    '*' is SeqSetup-internal shorthand for "the remaining cycles of this
    read". BCL Convert's OverrideCycles requires explicit counts, so a
    wildcard must be expanded into concrete cycles — equal to that read's
    run cycles minus any fixed UMI/mask cycles in the same segment — before
    the value ships in a Sample Sheet.
    """

    def test_passthrough_when_none(self):
        rc = RunCycles(151, 151, 10, 10)
        assert CycleCalculator.expand_override_cycles(None, rc) is None

    def test_passthrough_when_no_wildcard(self):
        rc = RunCycles(151, 151, 10, 10)
        assert (
            CycleCalculator.expand_override_cycles("Y151;I10;I10;Y151", rc)
            == "Y151;I10;I10;Y151"
        )

    def test_expands_read_wildcards(self):
        rc = RunCycles(151, 151, 10, 10)
        assert (
            CycleCalculator.expand_override_cycles("Y*;I8;I8;Y*", rc)
            == "Y151;I8;I8;Y151"
        )

    def test_subtracts_umi_cycles_from_wildcard(self):
        # U8 consumes 8 of Read1's 151 cycles; the wildcard takes the rest.
        rc = RunCycles(151, 151, 8, 8)
        assert (
            CycleCalculator.expand_override_cycles("U8Y*;I8;I8;Y*", rc)
            == "U8Y143;I8;I8;Y151"
        )

    def test_normalizes_comma_separators(self):
        rc = RunCycles(151, 151, 10, 10)
        assert (
            CycleCalculator.expand_override_cycles("Y*,I8,I8,Y*", rc)
            == "Y151;I8;I8;Y151"
        )

    def test_single_index_run_three_segments(self):
        # index2_cycles == 0 -> three positions: Read1, Index1, Read2.
        rc = RunCycles(151, 151, 10, 0)
        assert (
            CycleCalculator.expand_override_cycles("Y*;I10;Y*", rc)
            == "Y151;I10;Y151"
        )

    def test_single_end_run_three_segments(self):
        # read2_cycles == 0 -> three positions: Read1, Index1, Index2.
        rc = RunCycles(151, 0, 10, 10)
        assert (
            CycleCalculator.expand_override_cycles("Y*;I10;I10", rc)
            == "Y151;I10;I10"
        )

    def test_raises_without_run_cycles(self):
        with pytest.raises(ValueError):
            CycleCalculator.expand_override_cycles("Y*;I8;I8;Y*", None)

    def test_raises_on_segment_count_mismatch(self):
        # Run cycles imply four segments; two cannot be mapped — refuse to guess.
        rc = RunCycles(151, 151, 10, 10)
        with pytest.raises(ValueError):
            CycleCalculator.expand_override_cycles("Y*;Y*", rc)

    @pytest.mark.parametrize("value", [
        "Y*Q;I10;I10;Y*",       # stray letter after the wildcard was dropped
        "N2Y*5;I10;I10;Y*",     # digits after the wildcard were dropped
        "151;I10;I10;Y151",     # segment with no letter
        "Y151;I10;I10;Y151N",   # letter with no count
        "Y151;I10;I10;Y151;",   # empty trailing segment
        "Y151;;I10;I10;Y151",   # empty middle segment
    ])
    def test_raises_on_malformed_segment(self, value):
        # A typo must be refused at entry, never silently repaired into a
        # different (valid-looking) OverrideCycles.
        rc = RunCycles(151, 151, 10, 10)
        with pytest.raises(ValueError, match="not valid OverrideCycles"):
            CycleCalculator.expand_override_cycles(value, rc)

    def test_lowercase_input_still_accepted(self):
        rc = RunCycles(151, 151, 10, 10)
        assert (
            CycleCalculator.expand_override_cycles("y*;i8n2;i8n2;y*", rc)
            == "Y151;I8N2;I8N2;Y151"
        )

    def test_raises_on_multiple_wildcards_in_one_segment(self):
        # Two '*' in one segment would each claim all remaining cycles, silently
        # producing an over-count (e.g. Y151N151). Reject it visibly at entry
        # rather than storing a known-invalid value that only fails at Mark-Ready.
        rc = RunCycles(151, 151, 10, 10)
        with pytest.raises(ValueError):
            CycleCalculator.expand_override_cycles("Y*N*;I8;I8;Y*", rc)


class TestOverrideCyclesProblem:
    """One rule, used by Mark Ready and the save routes: does a sample's
    OverrideCycles fit the run's reads (spec 2026-09-27 run checks 1b, F11)?"""

    RC = RunCycles(151, 151, 10, 10)

    @pytest.mark.parametrize("value", [
        "Y151;I10;I10;Y151", "Y151;I8N2;I8N2;Y151", "U8Y143;I10;I10;Y151",
        "y151;i10;i10;y151", "Y151,I10,I10,Y151",
    ])
    def test_value_that_fits_has_no_problem(self, value):
        assert CycleCalculator.override_cycles_problem(value, self.RC) is None

    @pytest.mark.parametrize("value", ["151;I10;I10;Y151", "Y151N;I10;I10;Y151", "Y151;;I10;I10;Y151"])
    def test_malformed_value_is_invalid(self, value):
        assert CycleCalculator.override_cycles_problem(value, self.RC) == "invalid"

    @pytest.mark.parametrize("value", [
        pytest.param("Y151;I10;Y151", id="too-few-parts"),
        pytest.param("Y100;I10;I10;Y151", id="wrong-sum"),
        pytest.param("Y100;I8N2;I8N2;Y151", id="kit-pattern-Y100"),
        pytest.param("Y*;I10;I10;Y151", id="leftover-wildcard"),
    ])
    def test_value_that_does_not_fit_is_a_mismatch(self, value):
        assert CycleCalculator.override_cycles_problem(value, self.RC) == "mismatch"

    def test_zero_cycle_read_has_no_part(self):
        rc = RunCycles(151, 0, 10, 10)
        assert CycleCalculator.override_cycles_problem("Y151;I10;I10", rc) is None
        assert CycleCalculator.override_cycles_problem("Y151;I10;I10;Y0", rc) == "mismatch"

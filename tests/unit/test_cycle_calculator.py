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

    def test_validate_cycles_valid(self):
        """Test validation of valid cycle configuration."""
        cycles = RunCycles(
            read1_cycles=140, read2_cycles=140, index1_cycles=10, index2_cycles=10
        )
        errors = CycleCalculator.validate_cycles(cycles, 300)
        assert len(errors) == 0

    def test_validate_cycles_exceeds_kit(self):
        """Test validation when cycles exceed reagent kit."""
        cycles = RunCycles(
            read1_cycles=140, read2_cycles=140, index1_cycles=10, index2_cycles=10
        )
        errors = CycleCalculator.validate_cycles(cycles, 300)
        assert len(errors) == 0

        # Now test exceeding
        cycles = RunCycles(
            read1_cycles=200, read2_cycles=200, index1_cycles=10, index2_cycles=10
        )
        errors = CycleCalculator.validate_cycles(cycles, 420)
        assert len(errors) == 0  # 420 > 200+200+10+10=420, so valid

        # Test actually exceeding
        errors = CycleCalculator.validate_cycles(cycles, 300)
        assert len(errors) == 1
        assert "exceeds" in errors[0].lower()


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

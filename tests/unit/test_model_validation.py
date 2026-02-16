"""Tests for model input validation."""

import pytest

from seqsetup.models.index import Index, IndexKit, IndexType, IndexMode
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunCycles, SequencingRun


class TestIndexDNAValidation:
    """Tests for Index DNA sequence validation."""

    def test_valid_dna_sequence(self):
        index = Index(name="test", sequence="ATCGATCG", index_type=IndexType.I7)
        assert index.sequence == "ATCGATCG"

    def test_valid_sequence_with_n(self):
        index = Index(name="test", sequence="ATCNNNNN", index_type=IndexType.I7)
        assert index.sequence == "ATCNNNNN"

    def test_lowercase_normalized_to_uppercase(self):
        index = Index(name="test", sequence="atcgatcg", index_type=IndexType.I7)
        assert index.sequence == "ATCGATCG"

    def test_empty_sequence_allowed(self):
        index = Index(name="test", sequence="", index_type=IndexType.I7)
        assert index.sequence == ""

    def test_invalid_dna_characters_raises(self):
        with pytest.raises(ValueError, match="invalid characters"):
            Index(name="test", sequence="ATCGXYZ", index_type=IndexType.I7)

    def test_invalid_lowercase_detected_after_uppercase(self):
        with pytest.raises(ValueError, match="invalid characters"):
            Index(name="test", sequence="atcgxyz", index_type=IndexType.I7)

    def test_spaces_in_sequence_raises(self):
        with pytest.raises(ValueError, match="invalid characters"):
            Index(name="test", sequence="ATCG ATCG", index_type=IndexType.I7)

    def test_numeric_in_sequence_raises(self):
        with pytest.raises(ValueError, match="invalid characters"):
            Index(name="test", sequence="ATCG1234", index_type=IndexType.I7)


class TestIndexKitValidation:
    """Tests for IndexKit field clamping."""

    def test_default_index_cycles_positive(self):
        kit = IndexKit(name="test", default_index1_cycles=8, default_index2_cycles=10)
        assert kit.default_index1_cycles == 8
        assert kit.default_index2_cycles == 10

    def test_default_index_cycles_none_preserved(self):
        kit = IndexKit(name="test", default_index1_cycles=None, default_index2_cycles=None)
        assert kit.default_index1_cycles is None
        assert kit.default_index2_cycles is None

    def test_default_index_cycles_zero_clamped_to_one(self):
        kit = IndexKit(name="test", default_index1_cycles=0, default_index2_cycles=0)
        assert kit.default_index1_cycles == 1
        assert kit.default_index2_cycles == 1

    def test_default_index_cycles_negative_clamped(self):
        kit = IndexKit(name="test", default_index1_cycles=-5, default_index2_cycles=-1)
        assert kit.default_index1_cycles == 1
        assert kit.default_index2_cycles == 1


class TestSampleValidation:
    """Tests for Sample field clamping."""

    def test_barcode_mismatches_valid_range(self):
        sample = Sample(barcode_mismatches_index1=2, barcode_mismatches_index2=0)
        assert sample.barcode_mismatches_index1 == 2
        assert sample.barcode_mismatches_index2 == 0

    def test_barcode_mismatches_none_preserved(self):
        sample = Sample(barcode_mismatches_index1=None, barcode_mismatches_index2=None)
        assert sample.barcode_mismatches_index1 is None
        assert sample.barcode_mismatches_index2 is None

    def test_barcode_mismatches_clamped_high(self):
        sample = Sample(barcode_mismatches_index1=10, barcode_mismatches_index2=5)
        assert sample.barcode_mismatches_index1 == 3
        assert sample.barcode_mismatches_index2 == 3

    def test_barcode_mismatches_clamped_negative(self):
        sample = Sample(barcode_mismatches_index1=-1, barcode_mismatches_index2=-5)
        assert sample.barcode_mismatches_index1 == 0
        assert sample.barcode_mismatches_index2 == 0

    def test_index_cycles_positive(self):
        sample = Sample(index1_cycles=8, index2_cycles=10)
        assert sample.index1_cycles == 8
        assert sample.index2_cycles == 10

    def test_index_cycles_none_preserved(self):
        sample = Sample(index1_cycles=None, index2_cycles=None)
        assert sample.index1_cycles is None
        assert sample.index2_cycles is None

    def test_index_cycles_zero_clamped(self):
        sample = Sample(index1_cycles=0, index2_cycles=-3)
        assert sample.index1_cycles == 1
        assert sample.index2_cycles == 1

    def test_lanes_positive_integers_preserved(self):
        sample = Sample(lanes=[1, 2, 3])
        assert sample.lanes == [1, 2, 3]

    def test_lanes_negative_filtered(self):
        sample = Sample(lanes=[-1, 0, 1, 2])
        assert sample.lanes == [1, 2]

    def test_lanes_empty_preserved(self):
        sample = Sample(lanes=[])
        assert sample.lanes == []

    def test_lanes_float_values_filtered(self):
        """Float values like 1.0 are not integers and should be filtered out."""
        sample = Sample(lanes=[1.0, 2, 3.5])
        # Only int values > 0 survive the isinstance(lane, int) check
        assert sample.lanes == [2]

    def test_lanes_string_values_filtered(self):
        """Non-integer values in lanes list are filtered out."""
        sample = Sample(lanes=["1", 2, None])
        assert sample.lanes == [2]


class TestRunCyclesValidation:
    """Tests for RunCycles non-negative clamping."""

    def test_valid_cycles(self):
        rc = RunCycles(read1_cycles=151, read2_cycles=151, index1_cycles=10, index2_cycles=10)
        assert rc.read1_cycles == 151
        assert rc.read2_cycles == 151
        assert rc.index1_cycles == 10
        assert rc.index2_cycles == 10

    def test_negative_cycles_clamped_to_zero(self):
        rc = RunCycles(read1_cycles=-10, read2_cycles=-1, index1_cycles=-5, index2_cycles=-3)
        assert rc.read1_cycles == 0
        assert rc.read2_cycles == 0
        assert rc.index1_cycles == 0
        assert rc.index2_cycles == 0

    def test_zero_cycles_allowed(self):
        rc = RunCycles(read1_cycles=0, read2_cycles=0, index1_cycles=0, index2_cycles=0)
        assert rc.read1_cycles == 0
        assert rc.total_cycles == 0


class TestSequencingRunValidation:
    """Tests for SequencingRun field clamping."""

    def test_reagent_cycles_positive(self):
        run = SequencingRun(reagent_cycles=300)
        assert run.reagent_cycles == 300

    def test_reagent_cycles_zero_clamped(self):
        run = SequencingRun(reagent_cycles=0)
        assert run.reagent_cycles == 1

    def test_reagent_cycles_negative_clamped(self):
        run = SequencingRun(reagent_cycles=-100)
        assert run.reagent_cycles == 1

    def test_barcode_mismatches_valid(self):
        run = SequencingRun(barcode_mismatches_index1=2, barcode_mismatches_index2=0)
        assert run.barcode_mismatches_index1 == 2
        assert run.barcode_mismatches_index2 == 0

    def test_barcode_mismatches_clamped_high(self):
        run = SequencingRun(barcode_mismatches_index1=10, barcode_mismatches_index2=99)
        assert run.barcode_mismatches_index1 == 3
        assert run.barcode_mismatches_index2 == 3

    def test_barcode_mismatches_clamped_negative(self):
        run = SequencingRun(barcode_mismatches_index1=-1, barcode_mismatches_index2=-5)
        assert run.barcode_mismatches_index1 == 0
        assert run.barcode_mismatches_index2 == 0

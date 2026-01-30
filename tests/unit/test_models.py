"""Tests for data models."""

import pytest

from sequencing_run_setup.models.index import Index, IndexKit, IndexPair, IndexType
from sequencing_run_setup.models.sample import Sample
from sequencing_run_setup.models.sequencing_run import RunCycles, SequencingRun


class TestIndex:
    """Tests for Index model."""

    def test_index_creation(self):
        """Test creating an index."""
        index = Index(name="D701", sequence="ATTACTCG", index_type=IndexType.I7)
        assert index.name == "D701"
        assert index.sequence == "ATTACTCG"
        assert index.index_type == IndexType.I7
        assert index.length == 8

    def test_index_sequence_uppercase(self):
        """Test that sequences are normalized to uppercase."""
        index = Index(name="test", sequence="attactcg", index_type=IndexType.I7)
        assert index.sequence == "ATTACTCG"


class TestIndexPair:
    """Tests for IndexPair model."""

    def test_index_pair_creation(self, sample_index_pair):
        """Test creating an index pair."""
        assert sample_index_pair.name == "D701"
        assert sample_index_pair.index1_length == 8
        assert sample_index_pair.index2_length == 8

    def test_index_pair_sequences(self, sample_index_pair):
        """Test index pair sequence properties."""
        assert sample_index_pair.index1_sequence == "ATTACTCG"
        assert sample_index_pair.index2_sequence == "TATAGCCT"

    def test_single_index_pair(self):
        """Test index pair with only i7 (no i5)."""
        pair = IndexPair(
            id="single",
            name="Single",
            index1=Index(name="i7", sequence="ATCGATCG", index_type=IndexType.I7),
            index2=None,
        )
        assert pair.index1_length == 8
        assert pair.index2_length == 0
        assert pair.index2_sequence is None


class TestIndexKit:
    """Tests for IndexKit model."""

    def test_index_kit_creation(self, sample_index_kit):
        """Test creating an index kit."""
        assert sample_index_kit.name == "Test Kit"
        assert len(sample_index_kit.index_pairs) == 2

    def test_get_index_pair_by_id(self, sample_index_kit):
        """Test finding index pair by ID."""
        pair = sample_index_kit.get_index_pair_by_id("kit_D701")
        assert pair is not None
        assert pair.name == "D701"

    def test_get_index_pair_by_name(self, sample_index_kit):
        """Test finding index pair by name."""
        pair = sample_index_kit.get_index_pair_by_name("D702")
        assert pair is not None
        assert pair.id == "kit_D702"


class TestSample:
    """Tests for Sample model."""

    def test_sample_creation(self, sample_sample):
        """Test creating a sample."""
        assert sample_sample.sample_id == "Sample_001"
        assert sample_sample.has_index

    def test_sample_index_sequences(self, sample_sample):
        """Test sample index sequence properties."""
        assert sample_sample.index1_sequence == "ATTACTCG"
        assert sample_sample.index2_sequence == "TATAGCCT"

    def test_sample_without_index(self):
        """Test sample without index assigned."""
        sample = Sample(sample_id="Test")
        assert not sample.has_index
        assert sample.index1_sequence is None
        assert sample.index2_sequence is None

    def test_sample_clear_index(self, sample_sample):
        """Test clearing sample index."""
        sample_sample.override_cycles = "Y151;I8N2;I8N2;Y151"
        sample_sample.clear_index()
        assert not sample_sample.has_index
        assert sample_sample.override_cycles is None


class TestRunCycles:
    """Tests for RunCycles model."""

    def test_run_cycles_creation(self, sample_run_cycles):
        """Test creating run cycles."""
        assert sample_run_cycles.read1_cycles == 151
        assert sample_run_cycles.read2_cycles == 151
        assert sample_run_cycles.index1_cycles == 10
        assert sample_run_cycles.index2_cycles == 10

    def test_total_cycles(self, sample_run_cycles):
        """Test total cycles calculation."""
        assert sample_run_cycles.total_cycles == 322


class TestSequencingRun:
    """Tests for SequencingRun model."""

    def test_run_creation(self, sample_run):
        """Test creating a sequencing run."""
        assert sample_run.run_name == "TestRun_001"
        assert sample_run.has_samples
        assert len(sample_run.samples) == 1

    def test_all_samples_have_indexes(self, sample_run):
        """Test checking if all samples have indexes."""
        assert sample_run.all_samples_have_indexes

        # Add sample without index
        sample_run.add_sample(Sample(sample_id="NoIndex"))
        assert not sample_run.all_samples_have_indexes

"""Pytest fixtures for seqsetup tests."""

import pytest

from seqsetup.models.analysis import Analysis, AnalysisType, DRAGENPipeline
from seqsetup.models.index import Index, IndexKit, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)


@pytest.fixture
def sample_index_pair():
    """Create a sample index pair for testing."""
    return IndexPair(
        id="kit_D701",
        name="D701",
        index1=Index(name="D701", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="D501", sequence="TATAGCCT", index_type=IndexType.I5),
    )


@pytest.fixture
def sample_index_kit(sample_index_pair):
    """Create a sample index kit for testing."""
    return IndexKit(
        name="Test Kit",
        version="1.0",
        description="Test index adapter kit",
        index_pairs=[
            sample_index_pair,
            IndexPair(
                id="kit_D702",
                name="D702",
                index1=Index(name="D702", sequence="TCCGGAGA", index_type=IndexType.I7),
                index2=Index(name="D502", sequence="ATAGAGGC", index_type=IndexType.I5),
            ),
        ],
    )


@pytest.fixture
def sample_run_cycles():
    """Create sample run cycles for testing."""
    return RunCycles(
        read1_cycles=151,
        read2_cycles=151,
        index1_cycles=10,
        index2_cycles=10,
    )


@pytest.fixture
def sample_sample(sample_index_pair):
    """Create a sample for testing."""
    return Sample(
        sample_id="Sample_001",
        sample_name="Sample One",
        project="TestProject",
        index_pair=sample_index_pair,
    )


@pytest.fixture
def sample_run(sample_sample, sample_run_cycles):
    """Create a sample sequencing run for testing."""
    return SequencingRun(
        run_name="TestRun_001",
        run_description="Test sequencing run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        reagent_cycles=300,
        run_cycles=sample_run_cycles,
        samples=[sample_sample],
    )


@pytest.fixture
def sample_analysis():
    """Create a sample DRAGEN analysis for testing."""
    return Analysis(
        name="Germline Analysis",
        analysis_type=AnalysisType.DRAGEN_ONBOARD,
        dragen_pipeline=DRAGENPipeline.GERMLINE,
        reference_genome="hg38",
        sample_ids=["Sample_001"],
    )

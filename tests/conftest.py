"""Pytest fixtures for seqsetup tests."""

import os
import signal

import pytest

# A real per-test time limit, with no dependency. pytest-timeout is not in
# this environment and may not be added, and pytest.ini's
# faulthandler_timeout only *reports* a hang -- it prints every thread's
# traceback and lets the test run on. This ends it: the alarm raises inside
# the test, so it fails with the hanging frame in its traceback and the suite
# moves on (2026-10-18 batch, step 9).
#
# Two limits it has, and faulthandler covers the first: it can only interrupt
# the MAIN thread, so a hang inside another thread or a GIL-holding C call
# still needs the traceback dump; and neither covers a hang during
# collection. Keep both.
#
# 300 s is far above anything legitimate here: the slowest single test
# measured is about 50 s (tests/integration/test_index_safety_net.py), and the
# whole browser suite runs in about 110 s across eight parts.
TEST_TIME_LIMIT_SECONDS = 300


@pytest.hookimpl(wrapper=True, trylast=True)
def pytest_runtest_protocol(item):
    def _too_long(_signum, _frame):
        raise TimeoutError(
            f"{item.nodeid} ran longer than {TEST_TIME_LIMIT_SECONDS}s and was "
            f"stopped. The traceback below is where it was."
        )

    previous = signal.signal(signal.SIGALRM, _too_long)
    signal.setitimer(signal.ITIMER_REAL, TEST_TIME_LIMIT_SECONDS)
    try:
        return (yield)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)

# Pages show times in the TZ zone (seqsetup.utils.clock). Pin it so a test's
# expected text does not depend on the machine; a test that needs another
# zone sets TZ itself (monkeypatch.setenv).
os.environ["TZ"] = "UTC"

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


@pytest.fixture
def i100_with_index_first(monkeypatch):
    """The MiSeq i100 Series as a lab's own instrument file may still list it:
    Index-first (forward, the standard) and Read-first. The shipped i100 lists
    Read-first only (docs/design/2026-10-19-i100-read-first-design.md); a test
    of an instrument with two workflows, or of a forward workflow on an
    instrument whose RunInfo.xml marks a reversed i5, uses this."""
    from seqsetup.data import instruments

    monkeypatch.setitem(instruments._instruments["MiSeq i100 Series"], "i5_workflows", [
        {"name": "Index-first", "i5_read_orientation": "forward"},
        {"name": "Read-first", "i5_read_orientation": "reverse-complement"},
    ])

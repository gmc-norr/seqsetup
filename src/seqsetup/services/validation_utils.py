"""Shared utilities for validation services."""

import re
from collections import defaultdict
from functools import lru_cache
from typing import Optional

from ..data.instruments import get_lanes_for_flowcell
from ..models.sample import Sample
from ..models.sequencing_run import RunCycles, SequencingRun


def group_samples_by_lane(
    run: SequencingRun,
    all_lanes: Optional[list[int]] = None,
    instrument_config=None,
) -> dict[int, list[Sample]]:
    """Group samples by lane (empty lanes = all lanes).

    Args:
        run: Sequencing run
        all_lanes: Optional explicit list of all lanes. If None, derived from flowcell.
        instrument_config: Optional InstrumentConfig for DB overrides

    Returns:
        Dict mapping lane number to list of samples in that lane
    """
    if all_lanes is None:
        total_lanes = get_lanes_for_flowcell(
            run.instrument_platform, run.flowcell_type, instrument_config
        )
        all_lanes = list(range(1, total_lanes + 1))

    lane_samples: dict[int, list[Sample]] = defaultdict(list)
    for sample in run.samples:
        if sample.lanes:
            for lane in sample.lanes:
                lane_samples[lane].append(sample)
        else:
            for lane in all_lanes:
                lane_samples[lane].append(sample)
    return lane_samples


@lru_cache(maxsize=4096)
def _index_cycles_in(override_cycles: str, cycles: tuple[int, int, int, int],
                     index_num: int) -> Optional[int]:
    """The I cycles of one index read's part of an OverrideCycles, or None
    when the run has no such read or the value does not fit the run.
    ``cycles`` is (Read1, Read2, Index1, Index2)."""
    from .cycle_calculator import CycleCalculator

    run_cycles = RunCycles(*cycles)
    names = [name for name, _, _ in CycleCalculator.read_structure(run_cycles)]
    read = "Index1" if index_num == 1 else "Index2"
    if read not in names or CycleCalculator.override_cycles_problem(override_cycles, run_cycles):
        return None
    part = re.split(r"[;,]", override_cycles)[names.index(read)].upper()
    return sum(int(n) for n in re.findall(r"I(\d+)", part))


def index_cycles_read(sample: Sample, index_num: int, run=None) -> Optional[int]:
    """The index cycles BCL Convert reads for this sample's i7 (index_num=1)
    or i5 (2): the I cycles of that read's part of its OverrideCycles, typed,
    else computed (spec 2026-10-05 group A3, §4). 0 when the sample has no
    such index but the run has the read. None when it cannot be said: no run
    cycles, no such index read, no OverrideCycles (an unindexed sample), or
    one that does not fit the run (another check reports that)."""
    from .cycle_calculator import CycleCalculator

    rc = getattr(run, "run_cycles", None) if run is not None else None
    if rc is None:
        return None
    override = sample.override_cycles
    if not override:
        if not sample.has_index:
            return None
        override = CycleCalculator.calculate_override_cycles(sample, rc)
    return _index_cycles_in(
        override, (rc.read1_cycles, rc.read2_cycles, rc.index1_cycles, rc.index2_cycles),
        index_num,
    )


def effective_index_read_length(sample: Sample, index_num: int, run=None) -> int:
    """Number of index cycles actually READ for this sample's i7/i5.

    Demultiplexing matches an index only over the cycles it reads, not the
    full stored sequence. For a typed OverrideCycles that fits the run that
    is its I cycles (``index_cycles_read``; spec 2026-10-05 group A3, §4).
    Otherwise it is the sample's effective index length (``index{n}_cycles``
    if set, else the sequence length — see
    ``CycleCalculator._get_effective_index_length``), further bounded by the
    run's configured index read cycles when a run is supplied — the same
    number as the I cycles of the computed OverrideCycles. Comparing indexes
    over MORE bases than this misses collisions between samples whose masked
    tails differ but whose read cycles are identical; a run whose indexes are
    shorter than their cycles read does not pass Mark Ready.

    Args:
        sample: Sample whose index is being measured.
        index_num: 1 for index1 (i7), 2 for index2 (i5).
        run: Optional SequencingRun; when present, the run's index read
            cycles further cap the effective length.

    Returns:
        Effective index read length in cycles.
    """
    # Imported lazily to avoid any import-order coupling between the two
    # services modules (cycle_calculator imports models only, so no cycle).
    from .cycle_calculator import CycleCalculator

    if sample.override_cycles:
        read = index_cycles_read(sample, index_num, run)
        if read is not None:
            return read
    eff = CycleCalculator._get_effective_index_length(sample, index_num)
    run_cycles = getattr(run, "run_cycles", None) if run is not None else None
    if run_cycles is not None:
        configured = (
            run_cycles.index1_cycles if index_num == 1 else run_cycles.index2_cycles
        )
        if configured is not None:
            eff = min(eff, configured)
    return eff


def effective_index_sequence(sample: Sample, index_num: int, run=None) -> str:
    """The sample's i7 (index_num=1) or i5 (2) sequence truncated to the
    cycles actually read — i.e. the barcode demultiplexing compares.

    Returns "" when the sample has no such index. Truncation is from the
    start of the stored sequence, matching how ``hamming_distance`` and the
    OverrideCycles ``I{n}N{mask}`` segment treat the read cycles.
    """
    seq = sample.index1_sequence if index_num == 1 else sample.index2_sequence
    if not seq:
        return ""
    return seq[: effective_index_read_length(sample, index_num, run)]


def hamming_distance(seq1: str, seq2: str) -> int:
    """Calculate Hamming distance between two sequences.

    For sequences of different lengths, compares only up to the shorter length.
    This reflects how sequencing demultiplexing works - indexes are compared
    only for the number of cycles read.

    Args:
        seq1: First sequence
        seq2: Second sequence

    Returns:
        Number of positions where characters differ (up to shorter length)
    """
    min_len = min(len(seq1), len(seq2))
    return sum(c1 != c2 for c1, c2 in zip(seq1[:min_len], seq2[:min_len]))


_COMPLEMENT = str.maketrans("ACGTacgt", "TGCAtgca")


def reverse_complement(seq: str) -> str:
    """Return the reverse complement of a DNA sequence."""
    return seq.translate(_COMPLEMENT)[::-1]

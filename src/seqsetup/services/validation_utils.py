"""Shared utilities for validation services."""

from collections import defaultdict
from typing import Optional

from ..data.instruments import get_lanes_for_flowcell
from ..models.sample import Sample
from ..models.sequencing_run import SequencingRun


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


def effective_index_read_length(sample: Sample, index_num: int, run=None) -> int:
    """Number of index cycles actually READ for this sample's i7/i5.

    Demultiplexing matches an index only over the cycles it reads, not the
    full stored sequence. That count is the sample's effective index length
    (``index{n}_cycles`` if set, else the sequence length — see
    ``CycleCalculator._get_effective_index_length``), further bounded by the
    run's configured index read cycles when a run is supplied. Comparing
    indexes over MORE bases than this misses collisions between samples whose
    masked tails differ but whose read cycles are identical.

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

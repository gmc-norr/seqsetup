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

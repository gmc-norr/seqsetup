"""Index collision detection and distance calculation for sequencing runs."""

import logging
from collections import defaultdict
from typing import Optional

from ..data.instruments import get_lanes_for_flowcell
from ..models.sample import Sample
from ..models.sequencing_run import SequencingRun
from ..models.validation import IndexCollision, IndexDistanceMatrix
from .validation_utils import effective_index_sequence, hamming_distance


logger = logging.getLogger(__name__)

# Upper bound on the per-lane all-vs-all distance MATRIX (heatmap
# visualisation). The matrix is three n x n structures plus an n x n grid of
# rendered cells; building it for a lane of thousands of samples would exhaust
# memory/CPU. Collision DETECTION (validate_index_collisions) is a separate,
# memory-light O(n^2) scan that always runs — skipping the heatmap above this
# size does not weaken safety, only the visual aid. A heatmap larger than this
# is unreadable anyway.
MAX_HEATMAP_SAMPLES = 200


class IndexCollisionValidator:
    """Validator for detecting index collisions and calculating distance matrices."""

    # Legacy class attributes kept for any external callers that read them.
    # The actual collision thresholds are derived per-pair from the configured
    # barcode_mismatches_index1/index2 (run-level or per-sample) — see
    # _effective_mismatches and _check_sample_pair_collision below.
    I7_ONLY_MIN_DISTANCE = 3
    COMBINED_MIN_DISTANCE = 4

    @classmethod
    def _effective_mismatches(
        cls,
        sample1: Sample,
        sample2: Sample,
        run: SequencingRun,
        index_num: int,
        mismatches: Optional[dict] = None,
    ) -> int:
        """Return the pair-effective mismatch budget for the given index.

        Uses the larger of the two samples' numbers — a collision possible
        for either sample is a collision for the pair. A sample's number is
        the one the sheet gives BCL Convert when ``mismatches`` (the sheet
        plan's, keyed by (sample id, index number)) has it (spec 2026-10-05
        group A3, §2); else its per-sample value, falling back to the
        run-level default when that is None.
        """
        if index_num == 1:
            m1 = sample1.barcode_mismatches_index1
            m2 = sample2.barcode_mismatches_index1
            default = run.barcode_mismatches_index1
        else:
            m1 = sample1.barcode_mismatches_index2
            m2 = sample2.barcode_mismatches_index2
            default = run.barcode_mismatches_index2
        m1 = m1 if m1 is not None else default
        m2 = m2 if m2 is not None else default
        if mismatches:
            m1 = mismatches.get((sample1.id, index_num), m1)
            m2 = mismatches.get((sample2.id, index_num), m2)
        return max(m1, m2)

    @classmethod
    def validate_index_collisions(
        cls,
        run: SequencingRun,
        instrument_config=None,
        mismatches: Optional[dict] = None,
    ) -> list[IndexCollision]:
        """
        Detect index collisions within each lane.

        Indexes collide when their Hamming distance is <= the mismatch threshold.

        Args:
            run: Sequencing run to validate
            instrument_config: Optional InstrumentConfig for DB overrides
            mismatches: Optional sheet-plan mismatch numbers (see
                _effective_mismatches)

        Returns:
            List of IndexCollision objects describing each collision
        """
        collisions = []

        # Determine total lanes from flowcell
        total_lanes = get_lanes_for_flowcell(
            run.instrument_platform, run.flowcell_type, instrument_config
        )
        all_lanes = list(range(1, total_lanes + 1))

        # Group samples by lane
        lane_samples: dict[int, list[Sample]] = defaultdict(list)

        for sample in run.samples:
            if not sample.has_index:
                continue  # Skip samples without indexes

            if sample.lanes:
                # Sample assigned to specific lanes
                for lane in sample.lanes:
                    lane_samples[lane].append(sample)
            else:
                # Empty lanes = all lanes
                for lane in all_lanes:
                    lane_samples[lane].append(sample)

        # Check collisions in each lane
        for lane, samples in lane_samples.items():
            lane_collisions = cls._check_lane_collisions(samples, lane, run, mismatches)
            collisions.extend(lane_collisions)

        return collisions

    @classmethod
    def calculate_index_distances(
        cls,
        run: SequencingRun,
        instrument_config=None,
    ) -> dict[int, IndexDistanceMatrix]:
        """
        Calculate all-vs-all index distances per lane for heatmap visualization.

        Args:
            run: Sequencing run
            instrument_config: Optional InstrumentConfig for DB overrides

        Returns:
            Dict mapping lane number to IndexDistanceMatrix for samples in that lane
        """
        # Determine total lanes from flowcell
        total_lanes = get_lanes_for_flowcell(
            run.instrument_platform, run.flowcell_type, instrument_config
        )
        all_lanes = list(range(1, total_lanes + 1))

        # Group samples by lane
        lane_samples: dict[int, list[Sample]] = defaultdict(list)

        for sample in run.samples:
            if not sample.has_index:
                continue  # Skip samples without indexes

            if sample.lanes:
                # Sample assigned to specific lanes
                for lane in sample.lanes:
                    lane_samples[lane].append(sample)
            else:
                # Empty lanes = all lanes
                for lane in all_lanes:
                    lane_samples[lane].append(sample)

        # Calculate matrix for each lane
        matrices: dict[int, IndexDistanceMatrix] = {}

        for lane in sorted(lane_samples.keys()):
            samples = lane_samples[lane]
            if len(samples) < 2:
                continue
            # Skip the heatmap for very large lanes — the matrix is O(n^2)
            # memory and unreadable at that size; collision detection still
            # runs via validate_index_collisions. The bare module global is
            # read at call time so the cap stays tunable/testable.
            if len(samples) > MAX_HEATMAP_SAMPLES:
                logger.warning(
                    "Skipping index-distance heatmap for lane %s: %d samples "
                    "exceeds MAX_HEATMAP_SAMPLES (%d). Collisions are still "
                    "validated; only the visual heatmap is omitted.",
                    lane, len(samples), MAX_HEATMAP_SAMPLES,
                )
                continue
            matrices[lane] = cls._calculate_lane_distances(samples)

        return matrices

    @classmethod
    def _check_lane_collisions(
        cls,
        samples: list[Sample],
        lane: int,
        run: SequencingRun,
        mismatches: Optional[dict] = None,
    ) -> list[IndexCollision]:
        """
        Check for index collisions among samples in a single lane.

        Thresholds are derived per-pair from configured barcode_mismatches_*
        (see _check_sample_pair_collision).

        Args:
            samples: Samples in this lane
            lane: Lane number
            run: Parent run (used to source mismatch tolerances)

        Returns:
            List of collisions found in this lane
        """
        collisions = []
        n = len(samples)

        for i in range(n):
            for j in range(i + 1, n):
                sample1 = samples[i]
                sample2 = samples[j]

                collision = cls._check_sample_pair_collision(
                    sample1, sample2, lane, run, mismatches)
                if collision:
                    collisions.append(collision)

        return collisions

    @classmethod
    def _check_sample_pair_collision(
        cls,
        sample1: Sample,
        sample2: Sample,
        lane: int,
        run: SequencingRun = None,
        mismatches: Optional[dict] = None,
    ) -> Optional[IndexCollision]:
        """
        Check if two samples have colliding indexes.

        Thresholds derive from configured barcode_mismatches_*:
        - i7-only: collision iff d_i7 <= 2 * m_i7
        - i7+i5 combined: collision iff d_combined <= 2 * (m_i7 + m_i5)

        Where m_i7 (m_i5) is the larger of the two samples' configured
        barcode_mismatches_index1 (index2), falling back to the run-level
        default. This matches the standard "two reads can collide within
        their mismatch budgets when their Hamming distance is no more than
        twice the budget" reasoning used in _validate_mismatch_threshold.

        Args:
            sample1: First sample
            sample2: Second sample
            lane: Lane number
            run: Parent run (required for threshold derivation; kept Optional
                for backward compatibility with any external callers — falls
                back to legacy hardcoded thresholds when None)

        Returns:
            IndexCollision if collision detected, None otherwise
        """
        # Compare the indexes over the cycles actually READ at demultiplexing,
        # not the full stored sequences. Two indexes identical over their read
        # cycles but differing in a masked tail (OverrideCycles I{n}N{mask})
        # demultiplex to the same barcode and MUST be flagged as colliding.
        i7_seq1 = effective_index_sequence(sample1, 1, run)
        i7_seq2 = effective_index_sequence(sample2, 1, run)
        i5_seq1 = effective_index_sequence(sample1, 2, run)
        i5_seq2 = effective_index_sequence(sample2, 2, run)

        # Skip if either sample lacks i7 index
        if not i7_seq1 or not i7_seq2:
            return None

        # Calculate i7 distance
        i7_distance = hamming_distance(i7_seq1, i7_seq2)

        # Check if both samples have i5 indexes
        both_have_i5 = bool(i5_seq1 and i5_seq2)

        if both_have_i5:
            i5_distance = hamming_distance(i5_seq1, i5_seq2)
            combined_distance = i7_distance + i5_distance
            if run is not None:
                m_i7 = cls._effective_mismatches(sample1, sample2, run, 1, mismatches)
                m_i5 = cls._effective_mismatches(sample1, sample2, run, 2, mismatches)
                threshold = 2 * (m_i7 + m_i5)
            else:
                threshold = cls.COMBINED_MIN_DISTANCE - 1  # legacy fallback

            if combined_distance <= threshold:
                return IndexCollision(
                    sample1_id=sample1.id,
                    sample1_name=sample1.sample_id or sample1.sample_name or sample1.id,
                    sample2_id=sample2.id,
                    sample2_name=sample2.sample_id or sample2.sample_name or sample2.id,
                    lane=lane,
                    index_type="i7+i5",
                    sequence1=f"{i7_seq1}+{i5_seq1}",
                    sequence2=f"{i7_seq2}+{i5_seq2}",
                    hamming_distance=combined_distance,
                    mismatch_threshold=threshold,
                )
        else:
            if run is not None:
                m_i7 = cls._effective_mismatches(sample1, sample2, run, 1, mismatches)
                threshold = 2 * m_i7
            else:
                threshold = cls.I7_ONLY_MIN_DISTANCE - 1  # legacy fallback

            if i7_distance <= threshold:
                return IndexCollision(
                    sample1_id=sample1.id,
                    sample1_name=sample1.sample_id or sample1.sample_name or sample1.id,
                    sample2_id=sample2.id,
                    sample2_name=sample2.sample_id or sample2.sample_name or sample2.id,
                    lane=lane,
                    index_type="i7",
                    sequence1=i7_seq1,
                    sequence2=i7_seq2,
                    hamming_distance=i7_distance,
                    mismatch_threshold=threshold,
                )

        return None

    @classmethod
    def _calculate_lane_distances(cls, samples: list[Sample]) -> IndexDistanceMatrix:
        """
        Calculate distance matrix for samples in a single lane.

        Args:
            samples: Samples in this lane

        Returns:
            IndexDistanceMatrix with distances between sample pairs
        """
        n = len(samples)

        sample_ids = [s.id for s in samples]
        sample_names = [s.sample_id or s.sample_name or s.id for s in samples]

        # Initialize matrices with None (diagonal will stay None)
        i7_distances: list[list[Optional[int]]] = [
            [None for _ in range(n)] for _ in range(n)
        ]
        i5_distances: list[list[Optional[int]]] = [
            [None for _ in range(n)] for _ in range(n)
        ]
        combined_distances: list[list[Optional[int]]] = [
            [None for _ in range(n)] for _ in range(n)
        ]

        for i in range(n):
            for j in range(i + 1, n):
                sample1 = samples[i]
                sample2 = samples[j]

                # Calculate i7 distance
                i7_dist = None
                if sample1.index1_sequence and sample2.index1_sequence:
                    i7_dist = hamming_distance(
                        sample1.index1_sequence, sample2.index1_sequence
                    )
                i7_distances[i][j] = i7_dist
                i7_distances[j][i] = i7_dist  # Symmetric

                # Calculate i5 distance
                i5_dist = None
                if sample1.index2_sequence and sample2.index2_sequence:
                    i5_dist = hamming_distance(
                        sample1.index2_sequence, sample2.index2_sequence
                    )
                i5_distances[i][j] = i5_dist
                i5_distances[j][i] = i5_dist  # Symmetric

                # Calculate combined distance (sum of i7 + i5)
                combined_dist = None
                if i7_dist is not None and i5_dist is not None:
                    combined_dist = i7_dist + i5_dist
                elif i7_dist is not None:
                    combined_dist = i7_dist
                elif i5_dist is not None:
                    combined_dist = i5_dist
                combined_distances[i][j] = combined_dist
                combined_distances[j][i] = combined_dist  # Symmetric

        return IndexDistanceMatrix(
            sample_ids=sample_ids,
            sample_names=sample_names,
            i7_distances=i7_distances,
            i5_distances=i5_distances,
            combined_distances=combined_distances,
        )

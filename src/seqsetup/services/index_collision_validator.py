"""Index collision detection and distance calculation for sequencing runs."""

from collections import defaultdict
from typing import Optional

from ..data.instruments import get_lanes_for_flowcell
from ..models.sample import Sample
from ..models.sequencing_run import SequencingRun
from ..models.validation import IndexCollision, IndexDistanceMatrix
from .validation_utils import hamming_distance


class IndexCollisionValidator:
    """Validator for detecting index collisions and calculating distance matrices."""

    # Minimum safe distances for collision detection
    I7_ONLY_MIN_DISTANCE = 3  # i7-only: safe if distance >= 3
    COMBINED_MIN_DISTANCE = 4  # i7+i5 combined: safe if distance >= 4

    @classmethod
    def validate_index_collisions(
        cls,
        run: SequencingRun,
        instrument_config=None,
    ) -> list[IndexCollision]:
        """
        Detect index collisions within each lane.

        Indexes collide when their Hamming distance is <= the mismatch threshold.

        Args:
            run: Sequencing run to validate
            instrument_config: Optional InstrumentConfig for DB overrides

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
            lane_collisions = cls._check_lane_collisions(samples, lane, run)
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
            if len(samples) >= 2:
                matrices[lane] = cls._calculate_lane_distances(samples)

        return matrices

    @classmethod
    def _check_lane_collisions(
        cls,
        samples: list[Sample],
        lane: int,
        run: SequencingRun,
    ) -> list[IndexCollision]:
        """
        Check for index collisions among samples in a single lane.

        Collision thresholds:
        - i7 only (no i5): collision if i7 distance < 3
        - i7 + i5 combined: collision if combined distance < 4

        Args:
            samples: Samples in this lane
            lane: Lane number
            run: Parent run (unused, kept for API compatibility)

        Returns:
            List of collisions found in this lane
        """
        collisions = []
        n = len(samples)

        for i in range(n):
            for j in range(i + 1, n):
                sample1 = samples[i]
                sample2 = samples[j]

                collision = cls._check_sample_pair_collision(sample1, sample2, lane)
                if collision:
                    collisions.append(collision)

        return collisions

    @classmethod
    def _check_sample_pair_collision(
        cls,
        sample1: Sample,
        sample2: Sample,
        lane: int,
    ) -> Optional[IndexCollision]:
        """
        Check if two samples have colliding indexes.

        Uses combined distance when both samples have i5, otherwise i7-only distance.

        Thresholds:
        - i7 only: collision if distance < 3 (i.e., distance <= 2)
        - i7+i5 combined: collision if distance < 4 (i.e., distance <= 3)

        Args:
            sample1: First sample
            sample2: Second sample
            lane: Lane number

        Returns:
            IndexCollision if collision detected, None otherwise
        """
        i7_seq1 = sample1.index1_sequence
        i7_seq2 = sample2.index1_sequence
        i5_seq1 = sample1.index2_sequence
        i5_seq2 = sample2.index2_sequence

        # Skip if either sample lacks i7 index
        if not i7_seq1 or not i7_seq2:
            return None

        # Calculate i7 distance
        i7_distance = hamming_distance(i7_seq1, i7_seq2)

        # Check if both samples have i5 indexes
        both_have_i5 = bool(i5_seq1 and i5_seq2)

        if both_have_i5:
            # Use combined distance with threshold of 4
            i5_distance = hamming_distance(i5_seq1, i5_seq2)
            combined_distance = i7_distance + i5_distance
            threshold = cls.COMBINED_MIN_DISTANCE - 1  # collision if distance <= 3

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
            # Use i7-only distance with threshold of 3
            threshold = cls.I7_ONLY_MIN_DISTANCE - 1  # collision if distance <= 2

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

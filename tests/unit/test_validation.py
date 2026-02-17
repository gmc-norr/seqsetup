"""Tests for validation service."""

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    SequencingRun,
)
from seqsetup.services.validation import ValidationService
from seqsetup.services.validation_utils import hamming_distance, reverse_complement


class TestHammingDistance:
    """Tests for Hamming distance calculation."""

    def test_identical_sequences(self):
        """Identical sequences have distance 0."""
        dist = hamming_distance("ATCGATCG", "ATCGATCG")
        assert dist == 0

    def test_one_mismatch(self):
        """Single mismatch gives distance 1."""
        dist = hamming_distance("ATCGATCG", "ATCGATCC")
        assert dist == 1

    def test_two_mismatches(self):
        """Two mismatches gives distance 2."""
        dist = hamming_distance("ATCGATCG", "ATCGATTC")
        assert dist == 2

    def test_all_different(self):
        """All positions different."""
        dist = hamming_distance("AAAA", "TTTT")
        assert dist == 4

    def test_different_lengths_seq2_longer(self):
        """Different length sequences compare only up to shorter length."""
        dist = hamming_distance("ATCG", "ATCGAA")
        assert dist == 0  # 0 mismatches in 4-char overlap

    def test_different_lengths_seq1_longer(self):
        """Different length where seq1 is longer."""
        dist = hamming_distance("ATCGAA", "ATCG")
        assert dist == 0  # 0 mismatches in 4-char overlap

    def test_different_lengths_with_mismatches(self):
        """Different lengths with mismatches in overlap."""
        dist = hamming_distance("ATCG", "TTCGAA")
        assert dist == 1  # 1 mismatch in 4-char overlap (A vs T at pos 0)


class TestValidateSampleIds:
    """Tests for duplicate sample ID validation."""

    def test_no_duplicates(self):
        """No errors when all sample IDs are unique."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                Sample(sample_id="S1"),
                Sample(sample_id="S2"),
                Sample(sample_id="S3"),
            ],
        )
        errors = ValidationService.validate_sample_ids(run)
        assert len(errors) == 0

    def test_with_duplicates(self):
        """Errors reported for duplicate sample IDs."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                Sample(sample_id="S1"),
                Sample(sample_id="S1"),  # Duplicate
                Sample(sample_id="S2"),
            ],
        )
        errors = ValidationService.validate_sample_ids(run)
        assert len(errors) == 1
        assert "S1" in errors[0]
        assert "2 times" in errors[0]

    def test_multiple_duplicate_groups(self):
        """Multiple different duplicates."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                Sample(sample_id="S1"),
                Sample(sample_id="S1"),  # Duplicate of S1
                Sample(sample_id="S2"),
                Sample(sample_id="S2"),  # Duplicate of S2
                Sample(sample_id="S2"),  # Another S2
            ],
        )
        errors = ValidationService.validate_sample_ids(run)
        assert len(errors) == 2

    def test_empty_sample_ids_ignored(self):
        """Empty sample IDs are not flagged as duplicates."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                Sample(sample_id=""),
                Sample(sample_id=""),
                Sample(sample_id="S1"),
            ],
        )
        errors = ValidationService.validate_sample_ids(run)
        assert len(errors) == 0


class TestIndexCollisions:
    """Tests for index collision detection."""

    def _make_sample_with_indexes(
        self, sample_id: str, i7_seq: str, i5_seq: str = "", lanes: list[int] = None
    ) -> Sample:
        """Helper to create a sample with indexes."""
        sample = Sample(
            sample_id=sample_id,
            lanes=lanes or [],
            index_pair=IndexPair(
                id=f"pair_{sample_id}",
                name=f"Pair {sample_id}",
                index1=Index(name=f"i7_{sample_id}", sequence=i7_seq, index_type=IndexType.I7),
                index2=Index(name=f"i5_{sample_id}", sequence=i5_seq, index_type=IndexType.I5)
                if i5_seq
                else None,
            ),
        )
        return sample

    def test_no_collision_different_indexes(self):
        """No collision when indexes are sufficiently different."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            barcode_mismatches_index1=1,
            barcode_mismatches_index2=1,
            samples=[
                self._make_sample_with_indexes("S1", "AAAAAAAA", "CCCCCCCC", lanes=[1]),
                self._make_sample_with_indexes("S2", "TTTTTTTT", "GGGGGGGG", lanes=[1]),
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        assert len(collisions) == 0

    def test_collision_identical_indexes_i7_only(self):
        """Collision detected for identical i7 indexes when no i5."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCGATCG", "", lanes=[1]),
                self._make_sample_with_indexes("S2", "ATCGATCG", "", lanes=[1]),
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        assert len(collisions) == 1
        assert collisions[0].index_type == "i7"
        assert collisions[0].hamming_distance == 0
        # i7-only threshold: collision if distance <= 2
        assert collisions[0].mismatch_threshold == 2

    def test_collision_combined_identical(self):
        """Collision detected for identical dual-indexed samples."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCGATCG", "GCTAGCTA", lanes=[1]),
                self._make_sample_with_indexes("S2", "ATCGATCG", "GCTAGCTA", lanes=[1]),
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        assert len(collisions) == 1
        assert collisions[0].index_type == "i7+i5"
        assert collisions[0].hamming_distance == 0
        # Combined threshold: collision if distance <= 3
        assert collisions[0].mismatch_threshold == 3

    def test_collision_combined_within_threshold(self):
        """Collision when combined distance <= 3."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCGATCG", "GCTAGCTA", lanes=[1]),
                self._make_sample_with_indexes(
                    "S2", "ATCGATCC", "GCTAGCTC", lanes=[1]
                ),  # 1 diff in i7, 1 diff in i5 = 2 combined
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        assert len(collisions) == 1
        assert collisions[0].index_type == "i7+i5"
        assert collisions[0].hamming_distance == 2
        assert collisions[0].mismatch_threshold == 3

    def test_collision_i7_only_within_threshold(self):
        """Collision when i7-only distance <= 2."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCGATCG", "", lanes=[1]),
                self._make_sample_with_indexes(
                    "S2", "ATCGATCC", "", lanes=[1]
                ),  # 1 diff in i7
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        assert len(collisions) == 1
        assert collisions[0].index_type == "i7"
        assert collisions[0].hamming_distance == 1
        assert collisions[0].mismatch_threshold == 2

    def test_no_collision_i7_only_beyond_threshold(self):
        """No collision when i7-only distance >= 3."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCGATCG", "", lanes=[1]),
                self._make_sample_with_indexes(
                    "S2", "ATCGAAAA", "", lanes=[1]
                ),  # 3 diff in i7, no i5
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        assert len(collisions) == 0

    def test_no_collision_combined_beyond_threshold(self):
        """No collision when combined distance >= 4."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCGATCG", "GCTAGCTA", lanes=[1]),
                self._make_sample_with_indexes(
                    "S2", "AAAAATCG", "AAAAGCTA", lanes=[1]
                ),  # 3 diff in i7, 3 diff in i5 = 6 combined
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        assert len(collisions) == 0

    def test_no_collision_different_lanes(self):
        """No collision when samples are in different lanes."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            barcode_mismatches_index1=1,
            barcode_mismatches_index2=1,
            samples=[
                self._make_sample_with_indexes("S1", "ATCGATCG", "GCTAGCTA", lanes=[1]),
                self._make_sample_with_indexes(
                    "S2", "ATCGATCG", "GCTAGCTA", lanes=[2]
                ),  # Same indexes, different lane
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        assert len(collisions) == 0

    def test_collision_empty_lanes_means_all(self):
        """Samples with empty lanes appear in all lanes."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",  # 8 lanes
            samples=[
                self._make_sample_with_indexes(
                    "S1", "ATCGATCG", "", lanes=[]
                ),  # All lanes, i7 only
                self._make_sample_with_indexes(
                    "S2", "ATCGATCG", "", lanes=[3]
                ),  # Lane 3 only, i7 only (identical i7)
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        # Collision in lane 3 for i7 (identical indexes, distance=0)
        assert len(collisions) == 1
        assert collisions[0].lane == 3
        assert collisions[0].index_type == "i7"

    def test_collision_combined_reported_as_single(self):
        """Dual-indexed collision reported as single i7+i5 collision."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCGATCG", "GCTAGCTA", lanes=[1]),
                self._make_sample_with_indexes(
                    "S2", "ATCGATCG", "GCTAGCTA", lanes=[1]
                ),  # Both identical
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        # Single combined collision, not two separate i7/i5 collisions
        assert len(collisions) == 1
        assert collisions[0].index_type == "i7+i5"
        assert collisions[0].hamming_distance == 0

    def test_mixed_indexing_uses_i7_only_threshold(self):
        """When one sample lacks i5, uses i7-only threshold."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCGATCG", "GCTAGCTA", lanes=[1]),
                self._make_sample_with_indexes(
                    "S2", "ATCGATCG", "", lanes=[1]
                ),  # Same i7, no i5
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        # Uses i7-only threshold since S2 has no i5
        assert len(collisions) == 1
        assert collisions[0].index_type == "i7"
        assert collisions[0].hamming_distance == 0
        assert collisions[0].mismatch_threshold == 2  # i7-only threshold

    def test_samples_without_indexes_skipped(self):
        """Samples without indexes are skipped in collision detection."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            barcode_mismatches_index1=1,
            barcode_mismatches_index2=1,
            samples=[
                self._make_sample_with_indexes("S1", "ATCGATCG", "GCTAGCTA", lanes=[1]),
                Sample(sample_id="S2", lanes=[1]),  # No indexes
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        assert len(collisions) == 0


class TestDistanceMatrix:
    """Tests for per-lane distance matrix calculation."""

    def _make_sample_with_indexes(
        self, sample_id: str, i7_seq: str = "", i5_seq: str = "", lanes: list[int] = None
    ) -> Sample:
        """Helper to create a sample with indexes."""
        index_pair = None
        if i7_seq:
            index_pair = IndexPair(
                id=f"pair_{sample_id}",
                name=f"Pair {sample_id}",
                index1=Index(name=f"i7_{sample_id}", sequence=i7_seq, index_type=IndexType.I7),
                index2=Index(name=f"i5_{sample_id}", sequence=i5_seq, index_type=IndexType.I5)
                if i5_seq
                else None,
            )
        return Sample(sample_id=sample_id, index_pair=index_pair, lanes=lanes or [])

    def test_matrix_per_lane(self):
        """Matrices are created per lane."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "AAAA", "CCCC", lanes=[1]),
                self._make_sample_with_indexes("S2", "TTTT", "GGGG", lanes=[1]),
                self._make_sample_with_indexes("S3", "AAAA", "CCCC", lanes=[2]),
                self._make_sample_with_indexes("S4", "TTTT", "GGGG", lanes=[2]),
            ],
        )

        matrices = ValidationService.calculate_index_distances(run)
        assert 1 in matrices
        assert 2 in matrices
        assert len(matrices[1].sample_names) == 2
        assert len(matrices[2].sample_names) == 2

    def test_matrix_dimensions(self):
        """Matrix has correct dimensions for lane."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "AAAA", "CCCC", lanes=[1]),
                self._make_sample_with_indexes("S2", "TTTT", "GGGG", lanes=[1]),
                self._make_sample_with_indexes("S3", "AAAA", "CCCC", lanes=[1]),
            ],
        )

        matrices = ValidationService.calculate_index_distances(run)
        matrix = matrices[1]
        assert len(matrix.sample_names) == 3
        assert len(matrix.i7_distances) == 3
        assert len(matrix.i7_distances[0]) == 3
        assert len(matrix.i5_distances) == 3
        assert len(matrix.i5_distances[0]) == 3

    def test_matrix_symmetry(self):
        """Matrix is symmetric."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "AAAAAAAA", "CCCCCCCC", lanes=[1]),
                self._make_sample_with_indexes("S2", "TTTTTTTT", "GGGGGGGG", lanes=[1]),
            ],
        )

        matrices = ValidationService.calculate_index_distances(run)
        matrix = matrices[1]
        assert matrix.i7_distances[0][1] == matrix.i7_distances[1][0]
        assert matrix.i5_distances[0][1] == matrix.i5_distances[1][0]

    def test_matrix_diagonal_is_none(self):
        """Diagonal entries are None (no self-comparison)."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "AAAAAAAA", "CCCCCCCC", lanes=[1]),
                self._make_sample_with_indexes("S2", "TTTTTTTT", "GGGGGGGG", lanes=[1]),
            ],
        )

        matrices = ValidationService.calculate_index_distances(run)
        matrix = matrices[1]
        assert matrix.i7_distances[0][0] is None
        assert matrix.i7_distances[1][1] is None
        assert matrix.i5_distances[0][0] is None
        assert matrix.i5_distances[1][1] is None

    def test_matrix_correct_distances(self):
        """Matrix contains correct distance values."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "AAAA", "CCCC", lanes=[1]),
                self._make_sample_with_indexes("S2", "AATT", "CCGG", lanes=[1]),  # 2 diff each
            ],
        )

        matrices = ValidationService.calculate_index_distances(run)
        matrix = matrices[1]
        assert matrix.i7_distances[0][1] == 2
        assert matrix.i5_distances[0][1] == 2
        assert matrix.combined_distances[0][1] == 4  # 2 + 2

    def test_combined_distance_calculation(self):
        """Combined distance is sum of i7 and i5 distances."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "AAAA", "CCCC", lanes=[1]),
                self._make_sample_with_indexes("S2", "AAAT", "CCCG", lanes=[1]),  # 1 diff each
            ],
        )

        matrices = ValidationService.calculate_index_distances(run)
        matrix = matrices[1]
        assert matrix.i7_distances[0][1] == 1
        assert matrix.i5_distances[0][1] == 1
        assert matrix.combined_distances[0][1] == 2  # 1 + 1

    def test_combined_distance_only_i7(self):
        """Combined distance equals i7 when no i5 indexes."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "AAAA", "", lanes=[1]),  # No i5
                self._make_sample_with_indexes("S2", "AATT", "", lanes=[1]),  # No i5
            ],
        )

        matrices = ValidationService.calculate_index_distances(run)
        matrix = matrices[1]
        assert matrix.i7_distances[0][1] == 2
        assert matrix.i5_distances[0][1] is None
        assert matrix.combined_distances[0][1] == 2  # Just i7

    def test_combined_distance_diagonal_is_none(self):
        """Combined distance diagonal entries are None."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "AAAA", "CCCC", lanes=[1]),
                self._make_sample_with_indexes("S2", "TTTT", "GGGG", lanes=[1]),
            ],
        )

        matrices = ValidationService.calculate_index_distances(run)
        matrix = matrices[1]
        assert matrix.combined_distances[0][0] is None
        assert matrix.combined_distances[1][1] is None

    def test_matrix_empty_lanes_all_lanes(self):
        """Samples with empty lanes appear in all lanes."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",  # 8 lanes
            samples=[
                self._make_sample_with_indexes("S1", "AAAA", "CCCC", lanes=[]),  # All lanes
                self._make_sample_with_indexes("S2", "TTTT", "GGGG", lanes=[]),  # All lanes
            ],
        )

        matrices = ValidationService.calculate_index_distances(run)
        # Should have matrices for all 8 lanes
        assert len(matrices) == 8
        for lane in range(1, 9):
            assert lane in matrices
            assert len(matrices[lane].sample_names) == 2

    def test_matrix_uses_sample_id_for_names(self):
        """Matrix uses sample_id for display names."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("MySample1", "AAAA", "CCCC", lanes=[1]),
                self._make_sample_with_indexes("MySample2", "TTTT", "GGGG", lanes=[1]),
            ],
        )

        matrices = ValidationService.calculate_index_distances(run)
        assert matrices[1].sample_names == ["MySample1", "MySample2"]

    def test_single_sample_lane_no_matrix(self):
        """Lanes with single sample don't get a matrix."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "AAAA", "CCCC", lanes=[1]),
                self._make_sample_with_indexes("S2", "TTTT", "GGGG", lanes=[2]),
            ],
        )

        matrices = ValidationService.calculate_index_distances(run)
        # Neither lane has 2+ samples
        assert len(matrices) == 0


class TestValidateRun:
    """Tests for the main validate_run method."""

    def test_returns_validation_result(self):
        """validate_run returns a ValidationResult."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[Sample(sample_id="S1")],
        )

        result = ValidationService.validate_run(run)
        assert hasattr(result, "duplicate_sample_ids")
        assert hasattr(result, "index_collisions")
        assert hasattr(result, "distance_matrices")

    def test_has_errors_property(self):
        """has_errors property works correctly."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                Sample(sample_id="S1"),
                Sample(sample_id="S1"),  # Duplicate
            ],
        )

        result = ValidationService.validate_run(run)
        assert result.has_errors is True

    def test_no_errors_when_valid(self):
        """has_errors is False when run is valid."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                Sample(sample_id="S1"),
                Sample(sample_id="S2"),
            ],
        )

        result = ValidationService.validate_run(run)
        assert result.has_errors is False

    def test_empty_samples_returns_empty_matrices(self):
        """Empty samples list returns empty distance matrices dict."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[],
        )

        result = ValidationService.validate_run(run)
        assert result.distance_matrices == {}

    def test_validate_run_includes_color_balance(self):
        """validate_run includes color balance in result."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[Sample(sample_id="S1")],
        )

        result = ValidationService.validate_run(run)
        assert hasattr(result, "color_balance")


class TestColorBalance:
    """Tests for color balance calculation."""

    def _make_sample_with_indexes(
        self, sample_id: str, i7_seq: str = "", i5_seq: str = "", lanes: list[int] = None
    ) -> Sample:
        """Helper to create a sample with indexes."""
        index_pair = None
        if i7_seq:
            index_pair = IndexPair(
                id=f"pair_{sample_id}",
                name=f"Pair {sample_id}",
                index1=Index(name=f"i7_{sample_id}", sequence=i7_seq, index_type=IndexType.I7),
                index2=Index(name=f"i5_{sample_id}", sequence=i5_seq, index_type=IndexType.I5)
                if i5_seq
                else None,
            )
        return Sample(sample_id=sample_id, index_pair=index_pair, lanes=lanes or [])

    def test_color_balance_per_lane(self):
        """Color balance is calculated per lane."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCG", "GCTA", lanes=[1]),
                self._make_sample_with_indexes("S2", "ATCG", "GCTA", lanes=[2]),
            ],
        )

        color_balance = ValidationService.calculate_color_balance(run)
        assert 1 in color_balance
        assert 2 in color_balance

    def test_color_balance_base_counts(self):
        """Color balance correctly counts bases at each position."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "AAAA", "", lanes=[1]),
                self._make_sample_with_indexes("S2", "CCCC", "", lanes=[1]),
                self._make_sample_with_indexes("S3", "GGGG", "", lanes=[1]),
                self._make_sample_with_indexes("S4", "TTTT", "", lanes=[1]),
            ],
        )

        color_balance = ValidationService.calculate_color_balance(run)
        lane_balance = color_balance[1]
        i7_balance = lane_balance.i7_balance

        # Each position should have 1 of each base
        for pos in i7_balance.positions:
            assert pos.a_count == 1
            assert pos.c_count == 1
            assert pos.g_count == 1
            assert pos.t_count == 1

    def test_color_balance_channel1(self):
        """Channel 1 (Blue) includes A and C bases (XLEAP default)."""
        from seqsetup.models.validation import PositionColorBalance

        pos = PositionColorBalance(position=1, a_count=2, c_count=2, g_count=0, t_count=0)
        assert pos.channel1_count == 4  # A + C (Blue channel)
        assert pos.channel1_percent == 100.0

    def test_color_balance_channel2(self):
        """Channel 2 (Green) includes C and T bases (XLEAP default)."""
        from seqsetup.models.validation import PositionColorBalance

        pos = PositionColorBalance(position=1, a_count=0, c_count=2, g_count=0, t_count=2)
        assert pos.channel2_count == 4  # C + T (Green channel)
        assert pos.channel2_percent == 100.0

    def test_color_balance_status_ok(self):
        """Status is OK when both channels have good coverage."""
        from seqsetup.models.validation import ColorBalanceStatus, PositionColorBalance

        pos = PositionColorBalance(position=1, a_count=1, c_count=1, g_count=1, t_count=1)
        assert pos.status == ColorBalanceStatus.OK

    def test_color_balance_status_error_all_g(self):
        """Status is ERROR when all bases are G (no signal)."""
        from seqsetup.models.validation import ColorBalanceStatus, PositionColorBalance

        pos = PositionColorBalance(position=1, a_count=0, c_count=0, g_count=4, t_count=0)
        assert pos.status == ColorBalanceStatus.ERROR

    def test_color_balance_status_error_no_channel2(self):
        """Status is ERROR when no channel 2 signal (XLEAP: no C or T)."""
        from seqsetup.models.validation import ColorBalanceStatus, PositionColorBalance

        # Only A and G = channel2 (C+T) has 0 signal
        pos = PositionColorBalance(position=1, a_count=2, c_count=0, g_count=2, t_count=0)
        assert pos.status == ColorBalanceStatus.ERROR

    def test_color_balance_status_error_no_red(self):
        """Status is ERROR when no red signal (all A+G)."""
        from seqsetup.models.validation import ColorBalanceStatus, PositionColorBalance

        pos = PositionColorBalance(position=1, a_count=2, c_count=0, g_count=2, t_count=0)
        assert pos.status == ColorBalanceStatus.ERROR

    def test_color_balance_status_warning_low_channel1(self):
        """Status is WARNING when channel 1 is below 25%."""
        from seqsetup.models.validation import ColorBalanceStatus, PositionColorBalance

        # XLEAP: channel1 (Blue) = A+C. Only 1 A out of 10 = 10% channel1
        pos = PositionColorBalance(position=1, a_count=1, c_count=0, g_count=4, t_count=5)
        assert pos.channel1_percent < 25
        assert pos.status == ColorBalanceStatus.WARNING

    def test_color_balance_status_warning_low_channel2(self):
        """Status is WARNING when channel 2 is below 25%."""
        from seqsetup.models.validation import ColorBalanceStatus, PositionColorBalance

        # XLEAP: channel2 (Green) = C+T. Only 1 T out of 10 = 10% channel2
        pos = PositionColorBalance(position=1, a_count=5, c_count=0, g_count=4, t_count=1)
        assert pos.channel2_percent < 25
        assert pos.status == ColorBalanceStatus.WARNING

    def test_color_balance_empty_lanes_all_lanes(self):
        """Samples with empty lanes appear in all lanes."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",  # 8 lanes
            samples=[
                self._make_sample_with_indexes("S1", "ATCG", "GCTA", lanes=[]),
            ],
        )

        color_balance = ValidationService.calculate_color_balance(run)
        # Should have balance for all 8 lanes
        assert len(color_balance) == 8

    def test_color_balance_sample_count(self):
        """Lane color balance tracks sample count."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCG", "", lanes=[1]),
                self._make_sample_with_indexes("S2", "GCTA", "", lanes=[1]),
                self._make_sample_with_indexes("S3", "TTTT", "", lanes=[1]),
            ],
        )

        color_balance = ValidationService.calculate_color_balance(run)
        assert color_balance[1].sample_count == 3

    def test_color_balance_has_issues(self):
        """Lane has_issues detects problems."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "GGGG", "", lanes=[1]),  # All G = no signal
                self._make_sample_with_indexes("S2", "GGGG", "", lanes=[1]),
            ],
        )

        color_balance = ValidationService.calculate_color_balance(run)
        assert color_balance[1].has_issues is True

    def test_color_balance_no_issues_balanced(self):
        """Lane has_issues is False when balanced."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCG", "", lanes=[1]),
                self._make_sample_with_indexes("S2", "GCTA", "", lanes=[1]),
                self._make_sample_with_indexes("S3", "CGAT", "", lanes=[1]),
                self._make_sample_with_indexes("S4", "TAGC", "", lanes=[1]),
            ],
        )

        color_balance = ValidationService.calculate_color_balance(run)
        assert color_balance[1].has_issues is False

    def test_reverse_complement_helper(self):
        """reverse_complement produces correct output."""
        assert reverse_complement("ATCG") == "CGAT"
        assert reverse_complement("AAAA") == "TTTT"
        assert reverse_complement("GCTA") == "TAGC"
        assert reverse_complement("") == ""

    def test_color_balance_i5_forward_orientation(self):
        """i5 sequences are used as-is for forward orientation."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCG", "AAAA", lanes=[1]),
                self._make_sample_with_indexes("S2", "GCTA", "AAAA", lanes=[1]),
            ],
        )

        # Forward orientation: i5 sequences are AAAA (all A)
        color_balance = ValidationService.calculate_color_balance(run, i5_orientation="forward")
        i5_balance = color_balance[1].i5_balance
        assert i5_balance is not None
        # All A at every position
        for pos in i5_balance.positions:
            assert pos.a_count == 2
            assert pos.t_count == 0

    def test_color_balance_i5_reverse_complement_orientation(self):
        """i5 sequences are reverse-complemented for RC orientation."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "ATCG", "AAAA", lanes=[1]),
                self._make_sample_with_indexes("S2", "GCTA", "AAAA", lanes=[1]),
            ],
        )

        # Reverse-complement: AAAA -> TTTT, so all T at every position
        color_balance = ValidationService.calculate_color_balance(
            run, i5_orientation="reverse-complement"
        )
        i5_balance = color_balance[1].i5_balance
        assert i5_balance is not None
        for pos in i5_balance.positions:
            assert pos.a_count == 0
            assert pos.t_count == 2

    def test_color_balance_i5_rc_does_not_affect_i7(self):
        """i7 sequences are never reverse-complemented regardless of i5 orientation."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[
                self._make_sample_with_indexes("S1", "AAAA", "CCCC", lanes=[1]),
                self._make_sample_with_indexes("S2", "AAAA", "CCCC", lanes=[1]),
            ],
        )

        color_balance = ValidationService.calculate_color_balance(
            run, i5_orientation="reverse-complement"
        )
        i7_balance = color_balance[1].i7_balance
        assert i7_balance is not None
        # i7 should still be AAAA (not reverse-complemented)
        for pos in i7_balance.positions:
            assert pos.a_count == 2
            assert pos.t_count == 0

class TestValidationServiceEdgeCases:
    """Edge case tests for ValidationService."""

    def test_validate_empty_run(self):
        """Empty run (no samples) should validate without errors."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[],
        )

        errors = ValidationService.validate_sample_ids(run)
        assert len(errors) == 0

    def test_validate_single_sample_run(self):
        """Single sample run should validate without collisions."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[Sample(sample_id="ONLY_ONE")],
        )

        errors = ValidationService.validate_sample_ids(run)
        assert len(errors) == 0

    def test_validate_very_large_run(self):
        """Large run with many samples should be validated."""
        samples = [
            Sample(sample_id=f"SAMPLE_{i:05d}") for i in range(100)
        ]
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=samples,
        )

        errors = ValidationService.validate_sample_ids(run)
        assert len(errors) == 0  # All unique IDs

    def test_validate_all_samples_same_id(self):
        """All samples with same ID should trigger duplicate error."""
        samples = [
            Sample(sample_id="DUPLICATE") for _ in range(5)
        ]
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=samples,
        )

        errors = ValidationService.validate_sample_ids(run)
        assert len(errors) == 1
        assert "5 times" in errors[0]

    def test_hamming_distance_empty_strings(self):
        """Hamming distance for empty strings."""
        dist = hamming_distance("", "")
        assert dist == 0

    def test_hamming_distance_empty_vs_nonempty(self):
        """Hamming distance with one empty string."""
        dist = hamming_distance("", "ATCG")
        assert dist == 0  # 0-length overlap

    def test_hamming_distance_very_long_sequences(self):
        """Hamming distance for very long sequences."""
        seq1 = "ATCG" * 1000  # 4000 bp
        seq2 = "ATCG" * 1000
        dist = hamming_distance(seq1, seq2)
        assert dist == 0

    def test_hamming_distance_long_sequences_one_diff(self):
        """Hamming distance for long sequences with one difference."""
        seq1 = "A" + "ATCG" * 999 + "TC"
        seq2 = "T" + "ATCG" * 999 + "TC"
        dist = hamming_distance(seq1, seq2)
        assert dist == 1

    def test_reverse_complement_all_bases(self):
        """Reverse complement of all bases."""
        from seqsetup.services.validation_utils import reverse_complement
        assert reverse_complement("A") == "T"
        assert reverse_complement("T") == "A"
        assert reverse_complement("C") == "G"
        assert reverse_complement("G") == "C"

    def test_reverse_complement_with_n(self):
        """Reverse complement with N (ambiguous base)."""
        from seqsetup.services.validation_utils import reverse_complement
        assert reverse_complement("ATCN") == "NGAT"

    def test_reverse_complement_empty(self):
        """Reverse complement of empty string."""
        from seqsetup.services.validation_utils import reverse_complement
        assert reverse_complement("") == ""

    def test_reverse_complement_long_sequence(self):
        """Reverse complement of long sequence."""
        from seqsetup.services.validation_utils import reverse_complement
        original = "ATCGATCGATCG"
        rc = reverse_complement(original)
        # RC of ATCGATCGATCG = CGATCGATCGAT
        assert rc == "CGATCGATCGAT"

    def test_color_balance_empty_run(self):
        """Color balance for empty run returns empty dict."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[],
        )

        balance = ValidationService.calculate_color_balance(run)
        assert balance == {}

    def test_color_balance_single_sample(self):
        """Color balance for single sample."""
        sample = Sample(
            sample_id="S1",
            index1=Index(name="i7", sequence="ATCGATCG", index_type=IndexType.I7),
        )
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[sample],
        )

        balance = ValidationService.calculate_color_balance(run)
        # Should have calculation for this run
        assert len(balance) > 0

    def test_dark_cycles_empty_run(self):
        """Dark cycle detection for empty run returns empty list."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=[],
        )

        dark_cycles = ValidationService.validate_dark_cycles(run)
        assert dark_cycles == []

    def test_index_collision_lane_isolation(self):
        """Test that lane information is correctly used in collision detection."""
        from seqsetup.models.index import IndexPair
        
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            barcode_mismatches_index1=1,
            samples=[
                Sample(
                    sample_id="S1",
                    lanes=[1],
                    index_pair=IndexPair(
                        id="p1",
                        name="Pair1",
                        index1=Index(name="i7_1", sequence="ATCGATCG", index_type=IndexType.I7),
                        index2=Index(name="i5_1", sequence="GCTAGCTA", index_type=IndexType.I5),
                    ),
                ),
            ],
        )

        collisions = ValidationService.validate_index_collisions(run)
        # Single sample should have no collisions
        assert len(collisions) == 0

    def test_index_collision_many_samples_unique_indexes(self):
        """Many samples on same lane with well-separated indexes have no collisions."""
        from seqsetup.models.index import IndexPair

        # All pairs have combined hamming distance >= 4 (well above threshold of 3)
        base_sequences = [
            ("AAAAAAAA", "CCCCCCCC"),
            ("TTTTTTTT", "GGGGGGGG"),
            ("AATTAATT", "CCGGCCGG"),
            ("TTAATTAA", "GGCCGGCC"),
            ("AAAATTTT", "CCCCGGGG"),
            ("TTTTAAAA", "GGGGCCCC"),
            ("AATTTTAA", "CCGGGGCC"),
            ("TTAAAATT", "GGCCCCGG"),
            ("ATATATAT", "CGCGCGCG"),
        ]

        samples = [
            Sample(
                sample_id=f"S{i}",
                lanes=[1],
                index_pair=IndexPair(
                    id=f"p{i}",
                    name=f"Pair{i}",
                    index1=Index(
                        name=f"i7_{i}",
                        sequence=base_sequences[i][0],
                        index_type=IndexType.I7,
                    ),
                    index2=Index(
                        name=f"i5_{i}",
                        sequence=base_sequences[i][1],
                        index_type=IndexType.I5,
                    ),
                ),
            )
            for i in range(len(base_sequences))
        ]
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            samples=samples,
        )

        collisions = ValidationService.validate_index_collisions(run)
        assert len(collisions) == 0

    def test_validate_run_comprehensive(self):
        """Comprehensive validation of complete run."""
        from seqsetup.models.index import IndexPair
        
        run = SequencingRun(
            run_name="TestRun",
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            reagent_cycles=200,
            samples=[
                Sample(
                    sample_id="S1",
                    sample_name="Control",
                    index_pair=IndexPair(
                        id="p1",
                        name="Pair1",
                        index1=Index(name="i7_1", sequence="ATCGATCG", index_type=IndexType.I7),
                        index2=Index(name="i5_1", sequence="GCTAGCTA", index_type=IndexType.I5),
                    ),
                ),
                Sample(
                    sample_id="S2",
                    sample_name="Test",
                    index_pair=IndexPair(
                        id="p2",
                        name="Pair2",
                        index1=Index(name="i7_2", sequence="TTTTTTTT", index_type=IndexType.I7),
                        index2=Index(name="i5_2", sequence="AAAAAAAA", index_type=IndexType.I5),
                    ),
                ),
            ],
        )

        # Run through validation
        errors = ValidationService.validate_sample_ids(run)
        assert len(errors) == 0

        collisions = ValidationService.validate_index_collisions(run)
        assert len(collisions) == 0
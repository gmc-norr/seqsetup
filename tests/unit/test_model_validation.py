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

    def test_mixed_case_normalized(self):
        """Mixed case is normalized to uppercase."""
        index = Index(name="test", sequence="AtCgAtCg", index_type=IndexType.I7)
        assert index.sequence == "ATCGATCG"

    def test_all_n_sequence(self):
        """All N's is valid."""
        index = Index(name="test", sequence="NNNNNNNN", index_type=IndexType.I7)
        assert index.sequence == "NNNNNNNN"

    def test_very_long_sequence(self):
        """Very long sequence is preserved."""
        long_seq = "ATCG" * 100  # 400 bp
        index = Index(name="test", sequence=long_seq, index_type=IndexType.I7)
        assert index.sequence == long_seq
        assert len(index.sequence) == 400

    def test_single_base_sequence(self):
        """Single base sequence is valid."""
        index = Index(name="test", sequence="A", index_type=IndexType.I7)
        assert index.sequence == "A"

    def test_special_chars_in_sequence_raises(self):
        """Special characters not allowed."""
        with pytest.raises(ValueError, match="invalid characters"):
            Index(name="test", sequence="ATCG@#$", index_type=IndexType.I7)

    def test_tab_in_sequence_raises(self):
        """Tab characters are not allowed."""
        with pytest.raises(ValueError, match="invalid characters"):
            Index(name="test", sequence="ATCG\tATCG", index_type=IndexType.I7)

    def test_newline_in_sequence_raises(self):
        """Newlines are not allowed."""
        with pytest.raises(ValueError, match="invalid characters"):
            Index(name="test", sequence="ATCG\nATCG", index_type=IndexType.I7)

    def test_unicode_dna_like_raises(self):
        """Unicode-looking DNA-like characters are not allowed."""
        with pytest.raises(ValueError, match="invalid characters"):
            Index(name="test", sequence="AТ", index_type=IndexType.I7)  # Cyrillic T

    def test_index_type_i7(self):
        """I7 index type is preserved."""
        index = Index(name="test", sequence="ATCG", index_type=IndexType.I7)
        assert index.index_type == IndexType.I7

    def test_index_type_i5(self):
        """I5 index type is preserved."""
        index = Index(name="test", sequence="ATCG", index_type=IndexType.I5)
        assert index.index_type == IndexType.I5

    def test_index_name_empty_allowed(self):
        """Empty name is allowed at model level (routes validate)."""
        index = Index(name="", sequence="ATCG", index_type=IndexType.I7)
        assert index.name == ""

    def test_index_name_with_special_chars(self):
        """Index name can have special characters."""
        index = Index(name="Index-A_001.v2", sequence="ATCG", index_type=IndexType.I7)
        assert index.name == "Index-A_001.v2"


class TestIndexKitEdgeCases:
    """Additional edge case tests for IndexKit."""

    def test_index_kit_with_no_pairs(self):
        """Kit with empty index pairs list."""
        kit = IndexKit(name="empty_kit", index_pairs=[])
        assert kit.index_pairs == []

    def test_index_kit_mode_unique_dual(self):
        """IndexKit in unique_dual mode."""
        from seqsetup.models.index import IndexPair
        kit = IndexKit(
            name="test",
            index_mode=IndexMode.UNIQUE_DUAL,
            default_index1_cycles=8,
            default_index2_cycles=10,
            index_pairs=[
                IndexPair(
                    id="p1",
                    name="Pair1",
                    index1=Index(name="i7", sequence="ATCG", index_type=IndexType.I7),
                    index2=Index(name="i5", sequence="GCTA", index_type=IndexType.I5),
                )
            ],
        )
        assert kit.index_mode == IndexMode.UNIQUE_DUAL

    def test_index_kit_mode_combinatorial(self):
        """IndexKit in combinatorial mode."""
        from seqsetup.models.index import IndexPair
        kit = IndexKit(
            name="test",
            index_mode=IndexMode.COMBINATORIAL,
            default_index1_cycles=8,
            index_pairs=[
                IndexPair(
                    id="p1",
                    name="Pair1",
                    index1=Index(name="i7", sequence="ATCG", index_type=IndexType.I7),
                    index2=Index(name="i5", sequence="GCTA", index_type=IndexType.I5),
                )
            ],
        )
        assert kit.index_mode == IndexMode.COMBINATORIAL

    def test_index_kit_mode_single(self):
        """IndexKit in single mode."""
        from seqsetup.models.index import IndexPair
        kit = IndexKit(
            name="test",
            index_mode=IndexMode.SINGLE,
            default_index1_cycles=8,
            index_pairs=[
                IndexPair(
                    id="p1",
                    name="Pair1",
                    index1=Index(name="i7", sequence="ATCG", index_type=IndexType.I7),
                )
            ],
        )
        assert kit.index_mode == IndexMode.SINGLE

    def test_default_cycles_boundary_1(self):
        """Minimum cycle value of 1."""
        kit = IndexKit(name="test", default_index1_cycles=1)
        assert kit.default_index1_cycles == 1

    def test_default_cycles_boundary_large(self):
        """Large cycle values are preserved."""
        kit = IndexKit(name="test", default_index1_cycles=300)
        assert kit.default_index1_cycles == 300

    def test_kit_name_long(self):
        """Long kit name is preserved."""
        long_name = "Illumina_TruSeq_Stranded_mRNA_with_rRNA_removal_v2_001"
        kit = IndexKit(name=long_name)
        assert kit.name == long_name


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

    def test_all_cycles_very_large(self):
        """Very large cycle values are preserved."""
        rc = RunCycles(read1_cycles=10000, read2_cycles=10000, index1_cycles=1000, index2_cycles=1000)
        assert rc.read1_cycles == 10000
        assert rc.read2_cycles == 10000
        assert rc.index1_cycles == 1000
        assert rc.index2_cycles == 1000

    def test_total_cycles_sum(self):
        """total_cycles is sum of all four cycle types."""
        rc = RunCycles(read1_cycles=100, read2_cycles=100, index1_cycles=20, index2_cycles=20)
        assert rc.total_cycles == 240

    def test_single_read_cycles_only(self):
        """Single-end run with only read1 cycles."""
        rc = RunCycles(read1_cycles=151, read2_cycles=0, index1_cycles=10, index2_cycles=0)
        assert rc.total_cycles == 161
        assert rc.read2_cycles == 0
        assert rc.index2_cycles == 0

    def test_paired_end_with_indexes(self):
        """Standard paired-end with dual indexes."""
        rc = RunCycles(read1_cycles=151, read2_cycles=151, index1_cycles=8, index2_cycles=8)
        assert rc.total_cycles == 318

    def test_asymmetric_reads(self):
        """Asymmetric read lengths (common in RNA-seq)."""
        rc = RunCycles(read1_cycles=100, read2_cycles=50, index1_cycles=10, index2_cycles=0)
        assert rc.total_cycles == 160

    def test_boundary_read1_cycles_1(self):
        """Minimum meaningful read1 cycles."""
        rc = RunCycles(read1_cycles=1, read2_cycles=0, index1_cycles=0, index2_cycles=0)
        assert rc.total_cycles == 1

    def test_boundary_all_cycles_max_10000(self):
        """Maximum theoretical cycle values."""
        rc = RunCycles(read1_cycles=300, read2_cycles=300, index1_cycles=50, index2_cycles=50)
        assert rc.total_cycles == 700

    def test_novaseq_x_standard_config(self):
        """Realistic NovaSeq X SE configuration."""
        rc = RunCycles(read1_cycles=151, read2_cycles=0, index1_cycles=10, index2_cycles=0)
        assert rc.read1_cycles == 151
        assert rc.index1_cycles == 10
        assert rc.read2_cycles == 0

    def test_nextseq_550_standard_config(self):
        """Realistic NextSeq 550 PE configuration."""
        rc = RunCycles(read1_cycles=75, read2_cycles=75, index1_cycles=8, index2_cycles=0)
        assert rc.total_cycles == 158

    def test_miseq_v3_standard_config(self):
        """Realistic MiSeq v3 configuration."""
        rc = RunCycles(read1_cycles=301, read2_cycles=301, index1_cycles=8, index2_cycles=8)
        assert rc.total_cycles == 618

    def test_negative_boundaries_clamped(self):
        """Negative values are clamped to 0."""
        rc = RunCycles(read1_cycles=-1, read2_cycles=-100, index1_cycles=-5, index2_cycles=-999)
        assert rc.read1_cycles == 0
        assert rc.read2_cycles == 0
        assert rc.index1_cycles == 0
        assert rc.index2_cycles == 0

    def test_mixed_positive_negative(self):
        """Mix of positive and negative values."""
        rc = RunCycles(read1_cycles=100, read2_cycles=-50, index1_cycles=10, index2_cycles=-5)
        assert rc.read1_cycles == 100
        assert rc.read2_cycles == 0
        assert rc.index1_cycles == 10
        assert rc.index2_cycles == 0


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

class TestSampleStringFields:
    """Tests for Sample string field edge cases."""

    def test_sample_id_empty_allowed(self):
        sample = Sample(sample_id="")
        assert sample.sample_id == ""

    def test_sample_id_long_string(self):
        long_id = "A" * 500
        sample = Sample(sample_id=long_id)
        # Sample doesn't truncate - routes do
        assert len(sample.sample_id) == 500

    def test_sample_id_with_special_chars(self):
        sample = Sample(sample_id="SAMPLE-2024_001#v2")
        assert sample.sample_id == "SAMPLE-2024_001#v2"

    def test_sample_id_with_spaces(self):
        sample = Sample(sample_id="Sample With Spaces")
        assert sample.sample_id == "Sample With Spaces"

    def test_sample_id_unicode(self):
        sample = Sample(sample_id="Sample_café_Ñ")
        assert sample.sample_id == "Sample_café_Ñ"

    def test_sample_name_empty_allowed(self):
        sample = Sample(sample_name="")
        assert sample.sample_name == ""

    def test_sample_name_with_quotes(self):
        sample = Sample(sample_name='Sample "A" control')
        assert sample.sample_name == 'Sample "A" control'

    def test_project_empty_allowed(self):
        sample = Sample(project="")
        assert sample.project == ""

    def test_project_with_url_like_content(self):
        sample = Sample(project="proj://internal/data")
        assert sample.project == "proj://internal/data"

    def test_test_id_empty_allowed(self):
        sample = Sample(test_id="")
        assert sample.test_id == ""

    def test_test_id_with_dashes(self):
        sample = Sample(test_id="TEST-2024-001234")
        assert sample.test_id == "TEST-2024-001234"

    def test_worksheet_id_empty_allowed(self):
        sample = Sample(worksheet_id="")
        assert sample.worksheet_id == ""

    def test_worksheet_id_numeric_string(self):
        sample = Sample(worksheet_id="123456")
        assert sample.worksheet_id == "123456"

    def test_description_empty_allowed(self):
        sample = Sample(description="")
        assert sample.description == ""

    def test_description_multiline(self):
        multi = "Line 1\nLine 2\nLine 3"
        sample = Sample(description=multi)
        assert sample.description == multi

    def test_override_cycles_none_allowed(self):
        sample = Sample(override_cycles=None)
        assert sample.override_cycles is None

    def test_override_cycles_valid_pattern(self):
        sample = Sample(override_cycles="Y8N2Y*")
        assert sample.override_cycles == "Y8N2Y*"

    def test_override_cycles_complex_pattern(self):
        sample = Sample(override_cycles="U8Y*,I8,U8Y*")
        assert sample.override_cycles == "U8Y*,I8,U8Y*"

    def test_index1_override_pattern_none(self):
        sample = Sample(index1_override_pattern=None)
        assert sample.index1_override_pattern is None

    def test_index1_override_pattern_valid(self):
        sample = Sample(index1_override_pattern="I10")
        assert sample.index1_override_pattern == "I10"

    def test_index1_override_pattern_masked(self):
        sample = Sample(index1_override_pattern="I8N2")
        assert sample.index1_override_pattern == "I8N2"

    def test_read1_override_pattern_valid(self):
        sample = Sample(read1_override_pattern="N2Y*")
        assert sample.read1_override_pattern == "N2Y*"

    def test_read2_override_pattern_with_umi(self):
        sample = Sample(read2_override_pattern="U8Y*")
        assert sample.read2_override_pattern == "U8Y*"

    def test_metadata_empty_dict_allowed(self):
        sample = Sample(metadata={})
        assert sample.metadata == {}

    def test_metadata_complex_data(self):
        meta = {
            "platform": "Illumina",
            "version": 2,
            "tags": ["tag1", "tag2"],
            "nested": {"key": "value"},
        }
        sample = Sample(metadata=meta)
        assert sample.metadata == meta

    def test_analyses_empty_list(self):
        sample = Sample(analyses=[])
        assert sample.analyses == []

    def test_analyses_with_uuids(self):
        analysis_ids = [
            "550e8400-e29b-41d4-a716-446655440000",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        ]
        sample = Sample(analyses=analysis_ids)
        assert sample.analyses == analysis_ids

    def test_lanes_large_numbers(self):
        sample = Sample(lanes=[100, 200, 999])
        assert sample.lanes == [100, 200, 999]

    def test_lanes_unsorted_preserved(self):
        sample = Sample(lanes=[3, 1, 2])
        assert sample.lanes == [3, 1, 2]

    def test_lanes_duplicates_preserved(self):
        """Duplicates are preserved (filtering happens at assignment, not here)."""
        sample = Sample(lanes=[1, 1, 2, 2])
        assert sample.lanes == [1, 1, 2, 2]

    def test_lanes_mixed_types_filtered(self):
        """Non-int types are filtered away."""
        sample = Sample(lanes=[1, 2.5, "3", None, 4])
        assert sample.lanes == [1, 4]

    def test_index1_cycles_max_boundary(self):
        """Very large index1_cycles value gets clamped to at least 1."""
        sample = Sample(index1_cycles=9999)
        assert sample.index1_cycles == 9999  # No upper bound, only lower bound

    def test_index2_cycles_boundary(self):
        """index2_cycles also gets clamped to at least 1."""
        sample = Sample(index2_cycles=1)
        assert sample.index2_cycles == 1

    def test_clinical_example_complete_sample(self):
        """Real-world complete sample with all fields."""
        sample = Sample(
            sample_id="SAMPLE-2024-001",
            sample_name="Patient A (Control)",
            project="Study_XYZ",
            test_id="TEST-2024-001234",
            worksheet_id="WS-98765",
            lanes=[1, 2],
            barcode_mismatches_index1=1,
            barcode_mismatches_index2=1,
            index1_cycles=10,
            index2_cycles=10,
            override_cycles="Y*,I10,I10,Y*",
            description="Baseline sample",
        )
        assert sample.sample_id == "SAMPLE-2024-001"
        assert sample.barcode_mismatches_index1 == 1
        assert sample.lanes == [1, 2]
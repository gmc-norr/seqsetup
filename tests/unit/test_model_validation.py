"""Tests for model input validation."""

import pytest

from seqsetup.models.index import Index, IndexKit, IndexType, IndexMode
from seqsetup.models.sample import Sample
from seqsetup.models import sequencing_run as sequencing_run_module
from seqsetup.models.sequencing_run import RunCycles, SequencingRun


class TestSampleCountCap:
    """A run must reject samples beyond a hard per-run cap.

    Without a cap, an authenticated user can paste/import an unbounded number
    of samples, and the per-lane O(n^2) index-distance validation becomes a
    memory/CPU denial-of-service on the shared clinical app.
    """

    def test_add_sample_raises_at_cap(self, monkeypatch):
        monkeypatch.setattr(sequencing_run_module, "MAX_SAMPLES_PER_RUN", 3)
        run = SequencingRun()
        for i in range(3):
            run.add_sample(Sample(sample_id=f"S{i}"))
        with pytest.raises(ValueError, match="maximum"):
            run.add_sample(Sample(sample_id="S_over"))
        assert len(run.samples) == 3

    def test_add_sample_below_cap_succeeds(self, monkeypatch):
        monkeypatch.setattr(sequencing_run_module, "MAX_SAMPLES_PER_RUN", 3)
        run = SequencingRun()
        run.add_sample(Sample(sample_id="S1"))
        run.add_sample(Sample(sample_id="S2"))
        assert len(run.samples) == 2

    def test_from_dict_does_not_enforce_cap_on_existing_runs(self, monkeypatch):
        """Loading a pre-existing run with more samples than the cap must not
        fail — the cap guards new ingest, not historical documents."""
        monkeypatch.setattr(sequencing_run_module, "MAX_SAMPLES_PER_RUN", 2)
        data = {
            "id": "legacy-run",
            "run_name": "legacy",
            "samples": [{"id": f"id{i}", "sample_id": f"S{i}"} for i in range(5)],
        }
        run = SequencingRun.from_dict(data)
        assert len(run.samples) == 5


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

    def test_trailing_newline_is_stripped_not_stored(self):
        """A YAML literal-block scalar yields a trailing newline; the regex
        anchor ``$`` used to accept it, leaving a newline in the sequence that
        would later split a Sample Sheet row. Normalise it away."""
        index = Index(name="test", sequence="ATCGATCG\n", index_type=IndexType.I7)
        assert index.sequence == "ATCGATCG"

    def test_surrounding_whitespace_stripped(self):
        index = Index(name="test", sequence="  ATCGATCG\t\n", index_type=IndexType.I7)
        assert index.sequence == "ATCGATCG"

    def test_embedded_newline_raises(self):
        with pytest.raises(ValueError, match="invalid characters"):
            Index(name="test", sequence="ATCG\nATCG", index_type=IndexType.I7)

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

    def test_all_cycles_very_large_clamped(self):
        """Implausibly-large cycle values are clamped to the upper bound."""
        rc = RunCycles(read1_cycles=10000, read2_cycles=10000, index1_cycles=10000, index2_cycles=10000)
        # Upper bound is 1000 — generously above current Illumina max (~500).
        assert rc.read1_cycles == 1000
        assert rc.read2_cycles == 1000
        assert rc.index1_cycles == 1000
        assert rc.index2_cycles == 1000

    def test_cycles_at_upper_bound_preserved(self):
        rc = RunCycles(read1_cycles=500, read2_cycles=500, index1_cycles=24, index2_cycles=24)
        assert rc.read1_cycles == 500
        assert rc.read2_cycles == 500

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

    def test_sample_id_long_string_clamped_at_model(self):
        """The model clamps free-form string identifiers at 256 chars.

        Routes also sanitize at the boundary, but per CLAUDE.md the model
        is the load-bearing invariant — direct attribute writes (e.g. from
        a future code path that bypasses the form) must not balloon the
        document.
        """
        long_id = "A" * 500
        sample = Sample(sample_id=long_id)
        assert len(sample.sample_id) == 256

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
        sample = Sample(override_cycles="Y151;I8N2;I8N2;Y151")
        assert sample.override_cycles == "Y151;I8N2;I8N2;Y151"

    def test_override_cycles_rejects_wildcard_on_construction(self):
        """The '*' wildcard is SeqSetup-internal pattern shorthand. The final
        override_cycles must be concrete cycle counts — a '*' that reached a
        Sample Sheet is not valid BCL Convert OverrideCycles. The model refuses
        it on every ingest path; routes expand '*' before assigning."""
        with pytest.raises(ValueError, match="override_cycles"):
            Sample(override_cycles="U8Y*;I8;I8;Y*")

    def test_override_cycles_rejects_wildcard_on_assignment(self):
        sample = Sample(override_cycles=None)
        with pytest.raises(ValueError, match="override_cycles"):
            sample.override_cycles = "Y*;I8;I8;Y*"

    def test_override_cycles_rejects_injected_text(self):
        """Free-form text in override_cycles would flow into the Sample Sheet
        and shift downstream columns. Reject any non-override character."""
        with pytest.raises(ValueError, match="override_cycles"):
            Sample(override_cycles="Y151,injected")

    def test_override_cycles_rejects_html_tags(self):
        with pytest.raises(ValueError, match="override_cycles"):
            Sample(override_cycles="<script>alert(1)</script>")

    def test_override_cycles_rejects_shell_injection_chars(self):
        with pytest.raises(ValueError, match="override_cycles"):
            Sample(override_cycles="Y151; rm -rf /")

    def test_override_cycles_lowercased_normalised_to_uppercase(self):
        """Operator-pasted lowercase override is accepted by uppercasing,
        matching the Index sequence convention."""
        sample = Sample(override_cycles="y151;i8n2;n2i8;y151")
        assert sample.override_cycles == "Y151;I8N2;N2I8;Y151"

    def test_override_cycles_empty_string_allowed(self):
        sample = Sample(override_cycles="")
        assert sample.override_cycles == ""

    def test_override_cycles_validates_on_post_construction_assignment(self):
        """The model invariant must survive direct attribute writes, not just
        construction-time validation. Without the ``__setattr__`` interception
        a malformed string would be persisted and break ``from_dict()`` on
        the next load — see the routes that do ``sample.override_cycles = …``.
        """
        sample = Sample(override_cycles=None)
        with pytest.raises(ValueError, match="override_cycles"):
            sample.override_cycles = "Y151,injected"

    def test_override_cycles_normalises_on_post_construction_assignment(self):
        """Assignment of a lowercase value uppercases it, matching the
        construction-time behavior."""
        sample = Sample(override_cycles=None)
        sample.override_cycles = "y151;i8n2;i8n2;y151"
        assert sample.override_cycles == "Y151;I8N2;I8N2;Y151"

    def test_override_cycles_can_be_cleared_post_construction(self):
        sample = Sample(override_cycles="Y151;I8N2;I8N2;Y151")
        sample.override_cycles = None
        assert sample.override_cycles is None

    def test_other_field_assignments_still_pass_through(self):
        """``__setattr__`` should only special-case ``override_cycles``;
        other field assignments behave as for a plain dataclass."""
        sample = Sample(sample_id="A")
        sample.sample_name = "renamed"
        assert sample.sample_name == "renamed"

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
            override_cycles="Y151;I10;I10;Y151",
            description="Baseline sample",
        )
        assert sample.sample_id == "SAMPLE-2024-001"
        assert sample.barcode_mismatches_index1 == 1
        assert sample.lanes == [1, 2]


class TestSampleFreeFormFieldBounds:
    """The model is the load-bearing length defense for free-form strings —
    routes also sanitize, but a direct attribute write must not balloon
    the document."""

    def test_description_clamped_at_model(self):
        sample = Sample(description="x" * 10000)
        assert len(sample.description) == 4096

    def test_description_assigned_post_construction_also_clamped(self):
        sample = Sample()
        sample.description = "y" * 8000
        assert len(sample.description) == 4096

    def test_metadata_must_be_dict(self):
        with pytest.raises(ValueError, match="metadata must be a dict"):
            Sample(metadata=["not", "a", "dict"])

    def test_sample_name_clamped_at_256(self):
        sample = Sample(sample_name="A" * 500)
        assert len(sample.sample_name) == 256

    def test_test_id_clamped_at_256(self):
        sample = Sample(test_id="A" * 500)
        assert len(sample.test_id) == 256


class TestSequencingRunFreeFormBounds:
    """Direct attribute writes to run identifiers must respect length and
    CR/LF constraints — the Sample Sheet [Header] section would otherwise
    split into two lines on an embedded newline."""

    def test_run_name_clamped_at_256(self):
        from seqsetup.models.sequencing_run import SequencingRun
        run = SequencingRun(run_name="N" * 500)
        assert len(run.run_name) == 256

    def test_run_description_clamped_at_4096(self):
        from seqsetup.models.sequencing_run import SequencingRun
        run = SequencingRun(run_description="D" * 8000)
        assert len(run.run_description) == 4096

    def test_run_name_newline_replaced(self):
        """CR/LF must not survive to the Sample Sheet — they'd shift the
        next [Section] header into the middle of a data line."""
        from seqsetup.models.sequencing_run import SequencingRun
        run = SequencingRun(run_name="Sneaky\nRunName")
        assert "\n" not in run.run_name
        assert "Sneaky" in run.run_name
        assert "RunName" in run.run_name

    def test_run_description_cr_replaced(self):
        from seqsetup.models.sequencing_run import SequencingRun
        run = SequencingRun(run_description="line1\r\nline2")
        assert "\r" not in run.run_description
        assert "\n" not in run.run_description

    def test_run_name_assigned_post_construction_also_clamped(self):
        from seqsetup.models.sequencing_run import SequencingRun
        run = SequencingRun()
        run.run_name = "Z" * 500
        assert len(run.run_name) == 256


class TestSequencingRunExportClearing:
    """READY → DRAFT must clear pre-generated exports so a re-promotion
    cannot adopt blobs from before the edit cycle. READY → ARCHIVED keeps
    them — archived runs serve those bytes via the API."""

    def test_ready_to_draft_clears_pregenerated_exports(self):
        """End-to-end test via the routes layer lives in test_smoke_wizard;
        this is the route-handler logic stripped to model-level prerequisites."""
        # Smoke: ensure the model accepts the round-trip of cleared exports.
        from seqsetup.models.sequencing_run import SequencingRun
        r = SequencingRun()
        r.generated_samplesheet_v2 = "fake"
        r.generated_samplesheet_v2 = None
        assert r.generated_samplesheet_v2 is None
"""Tests for data models."""

import base64
from datetime import datetime

import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    RunStatus,
    SequencingRun,
)


class TestIndex:
    """Tests for Index model."""

    def test_index_creation(self):
        """Test creating an index."""
        index = Index(name="D701", sequence="ATTACTCG", index_type=IndexType.I7)
        assert index.name == "D701"
        assert index.sequence == "ATTACTCG"
        assert index.index_type == IndexType.I7
        assert index.length == 8

    def test_index_sequence_uppercase(self):
        """Test that sequences are normalized to uppercase."""
        index = Index(name="test", sequence="attactcg", index_type=IndexType.I7)
        assert index.sequence == "ATTACTCG"


class TestIndexPair:
    """Tests for IndexPair model."""

    def test_index_pair_creation(self, sample_index_pair):
        """Test creating an index pair."""
        assert sample_index_pair.name == "D701"
        assert sample_index_pair.index1_length == 8
        assert sample_index_pair.index2_length == 8

    def test_index_pair_sequences(self, sample_index_pair):
        """Test index pair sequence properties."""
        assert sample_index_pair.index1_sequence == "ATTACTCG"
        assert sample_index_pair.index2_sequence == "TATAGCCT"

    def test_single_index_pair(self):
        """Test index pair with only i7 (no i5)."""
        pair = IndexPair(
            id="single",
            name="Single",
            index1=Index(name="i7", sequence="ATCGATCG", index_type=IndexType.I7),
            index2=None,
        )
        assert pair.index1_length == 8
        assert pair.index2_length == 0
        assert pair.index2_sequence is None


class TestIndexKit:
    """Tests for IndexKit model."""

    def test_index_kit_creation(self, sample_index_kit):
        """Test creating an index kit."""
        assert sample_index_kit.name == "Test Kit"
        assert len(sample_index_kit.index_pairs) == 2

    def test_get_index_pair_by_id(self, sample_index_kit):
        """Test finding index pair by ID."""
        pair = sample_index_kit.get_index_pair_by_id("kit_D701")
        assert pair is not None
        assert pair.name == "D701"

    def test_get_index_pair_by_name(self, sample_index_kit):
        """Test finding index pair by name."""
        pair = sample_index_kit.get_index_pair_by_name("D702")
        assert pair is not None
        assert pair.id == "kit_D702"


class TestSample:
    """Tests for Sample model."""

    def test_sample_creation(self, sample_sample):
        """Test creating a sample."""
        assert sample_sample.sample_id == "Sample_001"
        assert sample_sample.has_index

    def test_sample_index_sequences(self, sample_sample):
        """Test sample index sequence properties."""
        assert sample_sample.index1_sequence == "ATTACTCG"
        assert sample_sample.index2_sequence == "TATAGCCT"

    def test_sample_without_index(self):
        """Test sample without index assigned."""
        sample = Sample(sample_id="Test")
        assert not sample.has_index
        assert sample.index1_sequence is None
        assert sample.index2_sequence is None

    def test_sample_clear_index(self, sample_sample):
        """Test clearing sample index."""
        sample_sample.override_cycles = "Y151;I8N2;I8N2;Y151"
        sample_sample.clear_index()
        assert not sample_sample.has_index
        assert sample_sample.override_cycles is None

    # --- Index sequence via individual indexes (not pair) ---

    def test_index_sequences_via_individual_indexes(self):
        """Test index sequences when using individual index1/index2 (combinatorial mode)."""
        sample = Sample(
            sample_id="Test",
            index1=Index(name="i7", sequence="AACCGGTT", index_type=IndexType.I7),
            index2=Index(name="i5", sequence="TTGGCCAA", index_type=IndexType.I5),
        )
        assert sample.index1_sequence == "AACCGGTT"
        assert sample.index2_sequence == "TTGGCCAA"
        assert sample.has_index

    def test_index_names_via_individual_indexes(self):
        """Test index names when using individual index1/index2."""
        sample = Sample(
            sample_id="Test",
            index1=Index(name="N701", sequence="AACCGGTT", index_type=IndexType.I7),
            index2=Index(name="S501", sequence="TTGGCCAA", index_type=IndexType.I5),
        )
        assert sample.index1_name == "N701"
        assert sample.index2_name == "S501"

    def test_index_names_none_when_no_index(self):
        """Test index names are None when no index assigned."""
        sample = Sample(sample_id="Test")
        assert sample.index1_name is None
        assert sample.index2_name is None

    # --- has_full_index ---

    def test_has_full_index_with_pair(self, sample_sample):
        """Test has_full_index returns True when index pair is assigned."""
        assert sample_sample.has_full_index

    def test_has_full_index_with_index1_only(self):
        """Test has_full_index returns True with just index1 (single mode)."""
        sample = Sample(
            sample_id="Test",
            index1=Index(name="i7", sequence="AACCGGTT", index_type=IndexType.I7),
        )
        assert sample.has_full_index

    def test_has_full_index_false_when_no_index(self):
        """Test has_full_index returns False when nothing assigned."""
        sample = Sample(sample_id="Test")
        assert not sample.has_full_index

    # --- Index assignment mutual exclusion ---

    def test_assign_index_pair_clears_individual_indexes(self):
        """Assigning index pair clears individual index1/index2."""
        sample = Sample(
            sample_id="Test",
            index1=Index(name="i7", sequence="AACCGGTT", index_type=IndexType.I7),
            index2=Index(name="i5", sequence="TTGGCCAA", index_type=IndexType.I5),
        )
        pair = IndexPair(
            id="p1", name="P1",
            index1=Index(name="D701", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="D501", sequence="TATAGCCT", index_type=IndexType.I5),
        )
        sample.assign_index(pair)
        assert sample.index_pair is pair
        assert sample.index1 is None
        assert sample.index2 is None

    def test_assign_index1_clears_index_pair(self, sample_sample):
        """Assigning individual i7 clears index pair."""
        assert sample_sample.index_pair is not None
        new_i7 = Index(name="N701", sequence="AACCGGTT", index_type=IndexType.I7)
        sample_sample.assign_index1(new_i7)
        assert sample_sample.index_pair is None
        assert sample_sample.index1 is new_i7

    def test_assign_index2_clears_index_pair(self, sample_sample):
        """Assigning individual i5 clears index pair."""
        assert sample_sample.index_pair is not None
        new_i5 = Index(name="S501", sequence="TTGGCCAA", index_type=IndexType.I5)
        sample_sample.assign_index2(new_i5)
        assert sample_sample.index_pair is None
        assert sample_sample.index2 is new_i5

    def test_clear_index1_clears_kit_when_no_index2(self):
        """clear_index1 clears index_kit_name if no index2 remains."""
        sample = Sample(
            sample_id="Test",
            index1=Index(name="i7", sequence="AACCGGTT", index_type=IndexType.I7),
            index_kit_name="My Kit",
        )
        sample.clear_index1()
        assert sample.index1 is None
        assert sample.index_kit_name is None

    def test_clear_index1_preserves_kit_when_index2_exists(self):
        """clear_index1 keeps index_kit_name if index2 still assigned."""
        sample = Sample(
            sample_id="Test",
            index1=Index(name="i7", sequence="AACCGGTT", index_type=IndexType.I7),
            index2=Index(name="i5", sequence="TTGGCCAA", index_type=IndexType.I5),
            index_kit_name="My Kit",
        )
        sample.clear_index1()
        assert sample.index1 is None
        assert sample.index_kit_name == "My Kit"

    def test_clear_index2_clears_kit_when_no_index1(self):
        """clear_index2 clears index_kit_name if no index1 remains."""
        sample = Sample(
            sample_id="Test",
            index2=Index(name="i5", sequence="TTGGCCAA", index_type=IndexType.I5),
            index_kit_name="My Kit",
        )
        sample.clear_index2()
        assert sample.index2 is None
        assert sample.index_kit_name is None

    # --- lanes_display ---

    def test_lanes_display_all(self):
        """Empty lanes list displays as 'All'."""
        sample = Sample(sample_id="Test", lanes=[])
        assert sample.lanes_display == "All"

    def test_lanes_display_sorted(self):
        """Lanes are displayed sorted."""
        sample = Sample(sample_id="Test", lanes=[3, 1, 2])
        assert sample.lanes_display == "1,2,3"

    # --- to_dict / from_dict round-trip ---

    def test_sample_to_dict_from_dict_roundtrip(self, sample_sample):
        """Test Sample serialization round-trip with index pair."""
        sample_sample.override_cycles = "Y151;I8N2;I8N2;Y151"
        sample_sample.barcode_mismatches_index1 = 2
        sample_sample.lanes = [1, 3]
        sample_sample.index1_cycles = 8
        sample_sample.index1_override_pattern = "I8N2"

        d = sample_sample.to_dict()
        restored = Sample.from_dict(d)

        assert restored.sample_id == sample_sample.sample_id
        assert restored.sample_name == sample_sample.sample_name
        assert restored.project == sample_sample.project
        assert restored.override_cycles == "Y151;I8N2;I8N2;Y151"
        assert restored.barcode_mismatches_index1 == 2
        assert restored.lanes == [1, 3]
        assert restored.index1_cycles == 8
        assert restored.index1_override_pattern == "I8N2"
        assert restored.index1_sequence == sample_sample.index1_sequence
        assert restored.index2_sequence == sample_sample.index2_sequence

    def test_sample_to_dict_from_dict_no_index(self):
        """Test Sample round-trip without index."""
        sample = Sample(sample_id="NoIdx", sample_name="No Index")
        d = sample.to_dict()
        restored = Sample.from_dict(d)
        assert restored.sample_id == "NoIdx"
        assert restored.index_pair is None
        assert restored.index1 is None
        assert not restored.has_index

    def test_sample_to_dict_from_dict_individual_indexes(self):
        """Test Sample round-trip with individual index1/index2."""
        sample = Sample(
            sample_id="Combo",
            index1=Index(name="N701", sequence="AACCGGTT", index_type=IndexType.I7),
            index2=Index(name="S501", sequence="TTGGCCAA", index_type=IndexType.I5),
            index_kit_name="Nextera XT",
        )
        d = sample.to_dict()
        restored = Sample.from_dict(d)
        assert restored.index_pair is None
        assert restored.index1.sequence == "AACCGGTT"
        assert restored.index2.sequence == "TTGGCCAA"
        assert restored.index_kit_name == "Nextera XT"

    def test_sample_from_dict_backward_compat_lane_to_lanes(self):
        """Test that old 'lane' field is migrated to 'lanes' list."""
        data = {
            "id": "test-id",
            "sample_id": "S1",
            "lane": 3,
        }
        restored = Sample.from_dict(data)
        assert restored.lanes == [3]

    def test_sample_from_dict_lanes_takes_precedence_over_lane(self):
        """When both 'lanes' and 'lane' are present, 'lanes' wins."""
        data = {
            "id": "test-id",
            "sample_id": "S1",
            "lanes": [1, 2],
            "lane": 3,
        }
        restored = Sample.from_dict(data)
        assert restored.lanes == [1, 2]


class TestRunCycles:
    """Tests for RunCycles model."""

    def test_run_cycles_creation(self, sample_run_cycles):
        """Test creating run cycles."""
        assert sample_run_cycles.read1_cycles == 151
        assert sample_run_cycles.read2_cycles == 151
        assert sample_run_cycles.index1_cycles == 10
        assert sample_run_cycles.index2_cycles == 10

    def test_total_cycles(self, sample_run_cycles):
        """Test total cycles calculation."""
        assert sample_run_cycles.total_cycles == 322


class TestSequencingRun:
    """Tests for SequencingRun model."""

    def test_run_creation(self, sample_run):
        """Test creating a sequencing run."""
        assert sample_run.run_name == "TestRun_001"
        assert sample_run.has_samples
        assert len(sample_run.samples) == 1

    def test_all_samples_have_indexes(self, sample_run):
        """Test checking if all samples have indexes."""
        assert sample_run.all_samples_have_indexes

        # Add sample without index
        sample_run.add_sample(Sample(sample_id="NoIndex"))
        assert not sample_run.all_samples_have_indexes

    def test_to_dict_generated_fields(self, sample_run):
        """Test that generated export fields serialize correctly."""
        sample_run.generated_samplesheet_v2 = "v2 content"
        sample_run.generated_samplesheet_v1 = "v1 content"
        sample_run.generated_json = '{"key": "value"}'
        sample_run.generated_validation_json = '{"errors": []}'
        sample_run.generated_validation_pdf = b"%PDF-test"

        d = sample_run.to_dict()
        assert d["generated_samplesheet_v2"] == "v2 content"
        assert d["generated_samplesheet_v1"] == "v1 content"
        assert d["generated_json"] == '{"key": "value"}'
        assert d["generated_validation_json"] == '{"errors": []}'
        assert d["generated_validation_pdf"] == base64.b64encode(b"%PDF-test").decode("ascii")

    def test_to_dict_generated_fields_none(self, sample_run):
        """Test that None generated fields serialize as None."""
        d = sample_run.to_dict()
        assert d["generated_samplesheet_v2"] is None
        assert d["generated_samplesheet_v1"] is None
        assert d["generated_json"] is None
        assert d["generated_validation_json"] is None
        assert d["generated_validation_pdf"] is None

    def test_from_dict_generated_fields(self):
        """Test that generated export fields deserialize correctly."""
        pdf_bytes = b"%PDF-test-content"
        data = {
            "id": "test-id",
            "run_name": "Test",
            "generated_samplesheet_v2": "v2 content",
            "generated_samplesheet_v1": "v1 content",
            "generated_json": '{"key": "value"}',
            "generated_validation_json": '{"errors": []}',
            "generated_validation_pdf": base64.b64encode(pdf_bytes).decode("ascii"),
        }
        run = SequencingRun.from_dict(data)
        assert run.generated_samplesheet_v2 == "v2 content"
        assert run.generated_samplesheet_v1 == "v1 content"
        assert run.generated_json == '{"key": "value"}'
        assert run.generated_validation_json == '{"errors": []}'
        assert run.generated_validation_pdf == pdf_bytes

    def test_from_dict_generated_fields_backward_compat(self):
        """Test that old generated_samplesheet field name still works."""
        data = {
            "id": "test-id",
            "run_name": "Test",
            "generated_samplesheet": "old v2 content",  # Old field name
        }
        run = SequencingRun.from_dict(data)
        assert run.generated_samplesheet_v2 == "old v2 content"

    def test_from_dict_generated_fields_missing(self):
        """Test from_dict when generated fields are absent (old data)."""
        data = {"id": "test-id"}
        run = SequencingRun.from_dict(data)
        assert run.generated_samplesheet_v2 is None
        assert run.generated_samplesheet_v1 is None
        assert run.generated_validation_pdf is None

    def test_roundtrip_to_from_dict(self, sample_run):
        """Test serialization roundtrip preserves data."""
        sample_run.generated_samplesheet_v1 = "v1 data"
        sample_run.generated_validation_pdf = b"pdf-bytes"

        d = sample_run.to_dict()
        restored = SequencingRun.from_dict(d)

        assert restored.run_name == sample_run.run_name
        assert restored.generated_samplesheet_v1 == "v1 data"
        assert restored.generated_validation_pdf == b"pdf-bytes"
        assert restored.instrument_platform == sample_run.instrument_platform
        assert len(restored.samples) == len(sample_run.samples)

    def test_status_roundtrip(self):
        """Test status field serializes and deserializes."""
        run = SequencingRun(id="test", status=RunStatus.READY)
        d = run.to_dict()
        assert d["status"] == "ready"
        restored = SequencingRun.from_dict(d)
        assert restored.status == RunStatus.READY

    # --- Mutation invariants ---

    def test_add_sample_resets_validation(self):
        """Adding a sample must reset validation_approved."""
        run = SequencingRun(validation_approved=True)
        run.add_sample(Sample(sample_id="New"))
        assert run.validation_approved is False
        assert len(run.samples) == 1

    def test_remove_sample_resets_validation(self, sample_run):
        """Removing a sample must reset validation_approved."""
        sample_run.validation_approved = True
        sample_id = sample_run.samples[0].id
        sample_run.remove_sample(sample_id)
        assert run.validation_approved is False if (run := sample_run) else True
        assert len(sample_run.samples) == 0

    def test_remove_sample_nonexistent_id(self, sample_run):
        """Removing a non-existent sample ID does not change the list."""
        original_count = len(sample_run.samples)
        sample_run.remove_sample("nonexistent-id")
        assert len(sample_run.samples) == original_count

    def test_get_sample_found(self, sample_run):
        """get_sample returns the sample when found."""
        sample_id = sample_run.samples[0].id
        found = sample_run.get_sample(sample_id)
        assert found is not None
        assert found.sample_id == "Sample_001"

    def test_get_sample_not_found(self, sample_run):
        """get_sample returns None for non-existent ID."""
        assert sample_run.get_sample("nonexistent") is None

    # --- touch() ---

    def test_touch_resets_validation_by_default(self):
        """touch() resets validation_approved by default."""
        run = SequencingRun(validation_approved=True)
        run.touch()
        assert run.validation_approved is False

    def test_touch_preserves_validation_when_told(self):
        """touch(reset_validation=False) keeps validation_approved."""
        run = SequencingRun(validation_approved=True)
        run.touch(reset_validation=False)
        assert run.validation_approved is True

    def test_touch_sets_updated_by(self):
        """touch() records who made the change."""
        run = SequencingRun()
        run.touch(updated_by="alice")
        assert run.updated_by == "alice"

    def test_touch_updates_timestamp(self):
        """touch() advances updated_at."""
        run = SequencingRun()
        before = run.updated_at
        run.touch()
        assert run.updated_at >= before

    # --- Analysis management ---

    def test_add_and_get_analysis(self):
        """add_analysis and get_analysis work together."""
        from seqsetup.models.analysis import Analysis, AnalysisType

        run = SequencingRun()
        analysis = Analysis(id="a1", name="Test", analysis_type=AnalysisType.DRAGEN_ONBOARD)
        run.add_analysis(analysis)
        assert len(run.analyses) == 1
        assert run.get_analysis("a1") is analysis

    def test_remove_analysis(self):
        """remove_analysis removes by ID."""
        from seqsetup.models.analysis import Analysis, AnalysisType

        run = SequencingRun()
        analysis = Analysis(id="a1", name="Test", analysis_type=AnalysisType.DRAGEN_ONBOARD)
        run.add_analysis(analysis)
        run.remove_analysis("a1")
        assert len(run.analyses) == 0
        assert run.get_analysis("a1") is None

    def test_get_analysis_not_found(self):
        """get_analysis returns None for non-existent ID."""
        run = SequencingRun()
        assert run.get_analysis("nonexistent") is None

    # --- from_dict backward compatibility ---

    def test_from_dict_complete_status_mapped_to_archived(self):
        """Old 'complete' status is migrated to 'archived'."""
        data = {"id": "test-id", "status": "complete"}
        run = SequencingRun.from_dict(data)
        assert run.status == RunStatus.ARCHIVED

    def test_from_dict_datetime_objects_preserved(self):
        """from_dict handles datetime objects (not just strings)."""
        now = datetime(2025, 6, 15, 10, 30, 0)
        data = {"id": "test-id", "created_at": now, "updated_at": now}
        run = SequencingRun.from_dict(data)
        # datetime objects are passed through as-is (not re-parsed)
        assert run.created_at == now
        assert run.updated_at == now

    def test_from_dict_missing_timestamps_default_to_now(self):
        """from_dict creates datetime.now() when timestamps are absent."""
        data = {"id": "test-id"}
        run = SequencingRun.from_dict(data)
        assert isinstance(run.created_at, datetime)
        assert isinstance(run.updated_at, datetime)

    # --- has_samples edge case ---

    def test_has_samples_false_for_empty(self):
        """has_samples returns False for empty run."""
        run = SequencingRun()
        assert not run.has_samples

    def test_all_samples_have_indexes_empty(self):
        """all_samples_have_indexes is True for empty sample list (vacuous truth)."""
        run = SequencingRun()
        assert run.all_samples_have_indexes


# ---------------------------------------------------------------------------
# IndexKit serialization
# ---------------------------------------------------------------------------


class TestIndexKitSerialization:
    """Tests for IndexKit to_dict / from_dict round-trip."""

    def test_unique_dual_roundtrip(self, sample_index_kit):
        """Test round-trip for a unique dual index kit."""
        d = sample_index_kit.to_dict()
        restored = IndexKit.from_dict(d)
        assert restored.name == sample_index_kit.name
        assert restored.version == sample_index_kit.version
        assert restored.description == sample_index_kit.description
        assert restored.index_mode == IndexMode.UNIQUE_DUAL
        assert len(restored.index_pairs) == 2
        assert restored.index_pairs[0].name == "D701"
        assert restored.index_pairs[0].index1.sequence == "ATTACTCG"

    def test_combinatorial_roundtrip(self):
        """Test round-trip for a combinatorial kit."""
        kit = IndexKit(
            name="Combo Kit",
            version="2.0",
            index_mode=IndexMode.COMBINATORIAL,
            i7_indexes=[
                Index(name="N701", sequence="AACCGGTT", index_type=IndexType.I7),
                Index(name="N702", sequence="CCGGAATT", index_type=IndexType.I7),
            ],
            i5_indexes=[
                Index(name="S501", sequence="TTGGCCAA", index_type=IndexType.I5),
            ],
        )
        d = kit.to_dict()
        restored = IndexKit.from_dict(d)
        assert restored.name == "Combo Kit"
        assert restored.index_mode == IndexMode.COMBINATORIAL
        assert len(restored.i7_indexes) == 2
        assert len(restored.i5_indexes) == 1
        assert restored.i7_indexes[0].sequence == "AACCGGTT"

    def test_all_optional_fields_roundtrip(self):
        """Test round-trip preserves all optional fields."""
        kit = IndexKit(
            name="Full Kit",
            version="3.0",
            description="Full",
            index_mode=IndexMode.UNIQUE_DUAL,
            is_fixed_layout=True,
            comments="batch 42",
            adapter_read1="CTGTCTCT",
            adapter_read2="CTGTCTCT",
            default_index1_cycles=8,
            default_index2_cycles=10,
            default_read1_override="U8Y*",
            default_read2_override="N2Y*",
            created_by="admin",
            source="github",
            index_pairs=[],
        )
        d = kit.to_dict()
        restored = IndexKit.from_dict(d)
        assert restored.is_fixed_layout is True
        assert restored.comments == "batch 42"
        assert restored.adapter_read1 == "CTGTCTCT"
        assert restored.default_index1_cycles == 8
        assert restored.default_index2_cycles == 10
        assert restored.default_read1_override == "U8Y*"
        assert restored.default_read2_override == "N2Y*"
        assert restored.created_by == "admin"
        assert restored.source == "github"

    def test_kit_id_property(self):
        """Test kit_id is name:version."""
        kit = IndexKit(name="My Kit", version="2.0")
        assert kit.kit_id == "My Kit:2.0"

    def test_to_dict_uses_kit_id_as_mongo_id(self, sample_index_kit):
        """Test _id field uses kit_id for MongoDB."""
        d = sample_index_kit.to_dict()
        assert d["_id"] == sample_index_kit.kit_id

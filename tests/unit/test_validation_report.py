"""Tests for validation report exporters (JSON and PDF)."""

import json

import pytest

from sequencing_run_setup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from sequencing_run_setup.models.sample import Sample
from sequencing_run_setup.models.index import Index, IndexPair, IndexType
from sequencing_run_setup.models.validation import (
    ColorBalanceStatus,
    ConfigurationError,
    DarkCycleError,
    IndexCollision,
    IndexColorBalance,
    IndexDistanceMatrix,
    LaneColorBalance,
    PositionColorBalance,
    SampleDarkCycleInfo,
    ValidationResult,
    ValidationSeverity,
)
from sequencing_run_setup.services.validation_report import (
    ValidationReportJSON,
    ValidationReportPDF,
)


@pytest.fixture
def basic_run():
    """Create a basic run for validation report testing."""
    return SequencingRun(
        id="test-run-123",
        run_name="Validation Test Run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 10, 10),
        samples=[
            Sample(
                id="s1",
                sample_id="S001",
                sample_name="Sample 1",
                index_pair=IndexPair(
                    id="p1",
                    name="D701",
                    index1=Index(name="D701", sequence="ATTACTCG", index_type=IndexType.I7),
                    index2=Index(name="D501", sequence="TATAGCCT", index_type=IndexType.I5),
                ),
            ),
            Sample(
                id="s2",
                sample_id="S002",
                sample_name="Sample 2",
                index_pair=IndexPair(
                    id="p2",
                    name="D702",
                    index1=Index(name="D702", sequence="TCCGGAGA", index_type=IndexType.I7),
                    index2=Index(name="D502", sequence="ATAGAGGC", index_type=IndexType.I5),
                ),
            ),
        ],
    )


@pytest.fixture
def empty_validation_result():
    """Create an empty validation result (no errors)."""
    return ValidationResult(
        duplicate_sample_ids=[],
        index_collisions=[],
        distance_matrices={},
    )


@pytest.fixture
def validation_result_with_errors():
    """Create a validation result with various errors."""
    collision = IndexCollision(
        sample1_id="s1",
        sample1_name="S001",
        sample2_id="s2",
        sample2_name="S002",
        lane=1,
        index_type="i7",
        sequence1="ATTACTCG",
        sequence2="ATTACTCA",
        hamming_distance=1,
        mismatch_threshold=1,
    )

    dark_error = DarkCycleError(
        sample_id="s1",
        sample_name="S001",
        index_type="i7",
        sequence="GGATTACT",
        dark_base="G",
    )

    config_error = ConfigurationError(
        severity=ValidationSeverity.ERROR,
        category="lane_out_of_range",
        message="Sample S001 assigned to lane 9, but flowcell has 8 lanes",
        lane=9,
    )

    config_warning = ConfigurationError(
        severity=ValidationSeverity.WARNING,
        category="index_length_mismatch",
        message="Mixed index lengths detected",
    )

    matrix = IndexDistanceMatrix(
        sample_ids=["s1", "s2"],
        sample_names=["S001", "S002"],
        i7_distances=[[None, 6], [6, None]],
        i5_distances=[[None, 5], [5, None]],
        combined_distances=[[None, 11], [11, None]],
    )

    cb_pos1 = PositionColorBalance(position=1, a_count=5, c_count=3, g_count=1, t_count=1)
    cb_pos2 = PositionColorBalance(position=2, a_count=0, c_count=0, g_count=10, t_count=0)
    i7_balance = IndexColorBalance(index_type="i7", positions=[cb_pos1, cb_pos2])
    lane_cb = LaneColorBalance(lane=1, sample_count=2, i7_balance=i7_balance)

    dark_sample = SampleDarkCycleInfo(
        sample_id="s1",
        sample_name="S001",
        i7_sequence="GGATTACT",
        i5_sequence="TATAGCCT",
        i5_read_sequence="AGGCTATA",
        dark_base="G",
        i7_leading_dark=2,
        i5_leading_dark=0,
    )

    return ValidationResult(
        duplicate_sample_ids=["Duplicate sample ID: S001"],
        index_collisions=[collision],
        distance_matrices={1: matrix},
        dark_cycle_errors=[dark_error],
        dark_cycle_samples=[dark_sample],
        color_balance={1: lane_cb},
        configuration_errors=[config_error, config_warning],
    )


class TestValidationReportJSON:
    """Tests for ValidationReportJSON."""

    def test_export_returns_valid_json(self, basic_run, empty_validation_result):
        result = ValidationReportJSON.export(basic_run, empty_validation_result)
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_export_run_metadata(self, basic_run, empty_validation_result):
        data = json.loads(ValidationReportJSON.export(basic_run, empty_validation_result))
        assert data["run_id"] == "test-run-123"
        assert data["run_name"] == "Validation Test Run"
        assert data["instrument"] == "NovaSeq X Series"
        assert data["flowcell"] == "10B"

    def test_export_timestamp(self, basic_run, empty_validation_result):
        data = json.loads(ValidationReportJSON.export(basic_run, empty_validation_result))
        assert "timestamp" in data

    def test_export_empty_summary(self, basic_run, empty_validation_result):
        data = json.loads(ValidationReportJSON.export(basic_run, empty_validation_result))
        summary = data["summary"]
        assert summary["error_count"] == 0
        assert summary["warning_count"] == 0
        assert summary["collision_count"] == 0
        assert summary["dark_cycle_error_count"] == 0

    def test_export_with_errors(self, basic_run, validation_result_with_errors):
        data = json.loads(ValidationReportJSON.export(basic_run, validation_result_with_errors))
        summary = data["summary"]
        assert summary["collision_count"] == 1
        assert summary["dark_cycle_error_count"] == 1
        assert summary["duplicate_sample_id_count"] == 1
        assert summary["configuration_error_count"] == 2

    def test_export_collision_details(self, basic_run, validation_result_with_errors):
        data = json.loads(ValidationReportJSON.export(basic_run, validation_result_with_errors))
        collisions = data["errors"]["index_collisions"]
        assert len(collisions) == 1
        c = collisions[0]
        assert c["lane"] == 1
        assert c["index_type"] == "i7"
        assert c["sample1_name"] == "S001"
        assert c["hamming_distance"] == 1

    def test_export_dark_cycle_details(self, basic_run, validation_result_with_errors):
        data = json.loads(ValidationReportJSON.export(basic_run, validation_result_with_errors))
        dark = data["errors"]["dark_cycle_errors"]
        assert len(dark) == 1
        assert dark[0]["sample_name"] == "S001"
        assert dark[0]["dark_base"] == "G"

    def test_export_configuration_errors(self, basic_run, validation_result_with_errors):
        data = json.loads(ValidationReportJSON.export(basic_run, validation_result_with_errors))
        config_errors = data["errors"]["configuration_errors"]
        assert len(config_errors) == 2
        assert config_errors[0]["severity"] == "error"
        assert config_errors[1]["severity"] == "warning"

    def test_export_per_lane_data(self, basic_run, validation_result_with_errors):
        data = json.loads(ValidationReportJSON.export(basic_run, validation_result_with_errors))
        per_lane = data["per_lane"]
        assert "1" in per_lane
        lane1 = per_lane["1"]
        assert lane1["sample_count"] == 2
        assert "distance_matrix" in lane1
        assert "color_balance" in lane1

    def test_export_distance_matrix_data(self, basic_run, validation_result_with_errors):
        data = json.loads(ValidationReportJSON.export(basic_run, validation_result_with_errors))
        dm = data["per_lane"]["1"]["distance_matrix"]
        assert dm["sample_names"] == ["S001", "S002"]
        assert dm["combined"][0][1] == 11

    def test_export_color_balance_data(self, basic_run, validation_result_with_errors):
        data = json.loads(ValidationReportJSON.export(basic_run, validation_result_with_errors))
        cb = data["per_lane"]["1"]["color_balance"]
        assert "i7" in cb
        positions = cb["i7"]
        assert len(positions) == 2
        assert positions[0]["position"] == 1


class TestValidationReportPDF:
    """Tests for ValidationReportPDF."""

    def test_export_returns_bytes(self, basic_run, empty_validation_result):
        result = ValidationReportPDF.export(basic_run, empty_validation_result)
        assert isinstance(result, bytes)

    def test_export_returns_valid_pdf(self, basic_run, empty_validation_result):
        result = ValidationReportPDF.export(basic_run, empty_validation_result)
        # PDF magic bytes
        assert result[:5] == b"%PDF-"

    def test_export_nonempty(self, basic_run, empty_validation_result):
        result = ValidationReportPDF.export(basic_run, empty_validation_result)
        assert len(result) > 100

    def test_export_with_errors_produces_pdf(self, basic_run, validation_result_with_errors):
        result = ValidationReportPDF.export(basic_run, validation_result_with_errors)
        assert result[:5] == b"%PDF-"
        # Should be larger than empty report due to heatmaps and tables
        empty_result = ValidationReportPDF.export(
            basic_run,
            ValidationResult(duplicate_sample_ids=[], index_collisions=[], distance_matrices={}),
        )
        assert len(result) > len(empty_result)

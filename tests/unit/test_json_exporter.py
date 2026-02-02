"""Tests for JSON metadata exporter."""

import json

import pytest

from sequencing_run_setup.models.analysis import Analysis, AnalysisType, DRAGENPipeline
from sequencing_run_setup.models.index import Index, IndexPair, IndexType
from sequencing_run_setup.models.sample import Sample
from sequencing_run_setup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from sequencing_run_setup.services.json_exporter import JSONExporter


@pytest.fixture
def run_with_samples():
    """Create a run with samples and index kit for JSON export testing."""
    pair1 = IndexPair(
        id="kit_D701",
        name="D701",
        index1=Index(name="D701", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="D501", sequence="TATAGCCT", index_type=IndexType.I5),
    )
    pair2 = IndexPair(
        id="kit_D702",
        name="D702",
        index1=Index(name="D702", sequence="TCCGGAGA", index_type=IndexType.I7),
        index2=Index(name="D502", sequence="ATAGAGGC", index_type=IndexType.I5),
    )
    return SequencingRun(
        id="test-run-id",
        run_name="JSON Test Run",
        run_description="Testing JSON export",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        reagent_cycles=300,
        run_cycles=RunCycles(151, 151, 10, 10),
        barcode_mismatches_index1=1,
        barcode_mismatches_index2=1,
        samples=[
            Sample(
                id="s1",
                sample_id="Sample_001",
                sample_name="Sample One",
                project="TestProject",
                index_pair=pair1,
            ),
            Sample(
                id="s2",
                sample_id="Sample_002",
                sample_name="Sample Two",
                project="TestProject",
                index_pair=pair2,
            ),
        ],
    )


class TestJSONExporter:
    """Tests for JSONExporter."""

    def test_export_returns_valid_json(self, run_with_samples):
        result = JSONExporter.export(run_with_samples)
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_export_run_metadata(self, run_with_samples):
        data = json.loads(JSONExporter.export(run_with_samples))
        assert data["id"] == "test-run-id"
        assert data["run_name"] == "JSON Test Run"
        assert data["run_description"] == "Testing JSON export"

    def test_export_instrument_info(self, run_with_samples):
        data = json.loads(JSONExporter.export(run_with_samples))
        assert data["instrument"]["platform"] == "NovaSeq X Series"
        assert data["instrument"]["flowcell_type"] == "10B"
        assert data["instrument"]["reagent_cycles"] == 300

    def test_export_cycles(self, run_with_samples):
        data = json.loads(JSONExporter.export(run_with_samples))
        assert data["cycles"]["read1_cycles"] == 151
        assert data["cycles"]["read2_cycles"] == 151
        assert data["cycles"]["index1_cycles"] == 10
        assert data["cycles"]["index2_cycles"] == 10

    def test_export_bclconvert_settings(self, run_with_samples):
        data = json.loads(JSONExporter.export(run_with_samples))
        settings = data["bclconvert_settings"]
        assert settings["barcode_mismatches_index1"] == 1
        assert settings["barcode_mismatches_index2"] == 1
        assert settings["adapter_behavior"] == "trim"

    def test_export_samples(self, run_with_samples):
        data = json.loads(JSONExporter.export(run_with_samples))
        assert len(data["samples"]) == 2

        s1 = data["samples"][0]
        assert s1["sample_id"] == "Sample_001"
        assert s1["sample_name"] == "Sample One"
        assert s1["project"] == "TestProject"
        assert s1["index1"]["name"] == "D701"
        assert s1["index1"]["sequence"] == "ATTACTCG"
        assert s1["index2"]["name"] == "D501"
        assert s1["index2"]["sequence"] == "TATAGCCT"

    def test_export_sample_without_index(self):
        run = SequencingRun(
            id="test",
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[Sample(id="s1", sample_id="NoIdx")],
        )
        data = json.loads(JSONExporter.export(run))
        s = data["samples"][0]
        assert s["index1"] is None
        assert s["index2"] is None

    def test_export_analyses(self):
        analysis = Analysis(
            id="a1",
            name="Germline",
            analysis_type=AnalysisType.DRAGEN_ONBOARD,
            dragen_pipeline=DRAGENPipeline.GERMLINE,
            reference_genome="hg38",
            sample_ids=["Sample_001"],
        )
        run = SequencingRun(
            id="test",
            run_cycles=RunCycles(151, 151, 10, 10),
            analyses=[analysis],
        )
        data = json.loads(JSONExporter.export(run))
        assert len(data["analyses"]) == 1
        a = data["analyses"][0]
        assert a["name"] == "Germline"
        assert a["type"] == "dragen_onboard"
        assert a["dragen_pipeline"] == "dragen_germline"
        assert a["reference_genome"] == "hg38"
        assert a["sample_ids"] == ["Sample_001"]

    def test_export_empty_run(self):
        run = SequencingRun(id="empty", run_name="Empty Run")
        data = json.loads(JSONExporter.export(run))
        assert data["samples"] == []
        assert data["analyses"] == []
        assert data["cycles"] is None

    def test_export_computed_override_cycles(self, run_with_samples):
        """Verify override cycles are computed from index lengths."""
        data = json.loads(JSONExporter.export(run_with_samples))
        # Samples have 8bp indexes with 10-cycle run -> should get computed override
        s1 = data["samples"][0]
        assert s1["override_cycles"] is not None
        assert "I8" in s1["override_cycles"]

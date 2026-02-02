"""Tests for SampleSheet v1 (IEM) exporter."""

import pytest
from datetime import datetime

from sequencing_run_setup.models.index import Index, IndexPair, IndexType
from sequencing_run_setup.models.sample import Sample
from sequencing_run_setup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from sequencing_run_setup.services.samplesheet_v1_exporter import (
    SampleSheetV1Exporter,
    _reverse_complement,
)


class TestReverseComplement:
    """Tests for the _reverse_complement helper."""

    def test_simple_sequence(self):
        assert _reverse_complement("ATCG") == "CGAT"

    def test_all_bases(self):
        assert _reverse_complement("ACGT") == "ACGT"

    def test_single_base(self):
        assert _reverse_complement("A") == "T"
        assert _reverse_complement("G") == "C"

    def test_lowercase(self):
        assert _reverse_complement("atcg") == "cgat"

    def test_poly_a(self):
        assert _reverse_complement("AAAA") == "TTTT"

    def test_longer_sequence(self):
        assert _reverse_complement("ATTACTCG") == "CGAGTAAT"


class TestSampleSheetV1ExporterSupports:
    """Tests for the supports() class method."""

    def test_supports_miseq(self):
        assert SampleSheetV1Exporter.supports(InstrumentPlatform.MISEQ) is True

    def test_supports_novaseq_6000(self):
        assert SampleSheetV1Exporter.supports(InstrumentPlatform.NOVASEQ_6000) is True

    def test_not_supports_novaseq_x(self):
        assert SampleSheetV1Exporter.supports(InstrumentPlatform.NOVASEQ_X) is False

    def test_not_supports_miseq_i100(self):
        assert SampleSheetV1Exporter.supports(InstrumentPlatform.MISEQ_I100) is False

    def test_not_supports_nextseq(self):
        assert SampleSheetV1Exporter.supports(InstrumentPlatform.NEXTSEQ_500_550) is False


@pytest.fixture
def miseq_run():
    """Create a MiSeq run for testing."""
    return SequencingRun(
        run_name="MiSeq Test Run",
        run_description="Test description",
        instrument_platform=InstrumentPlatform.MISEQ,
        flowcell_type="Standard",
        run_cycles=RunCycles(150, 150, 10, 10),
        created_by="testuser",
        created_at=datetime(2025, 6, 15, 10, 30, 0),
        samples=[
            Sample(
                sample_id="Sample_001",
                sample_name="Sample One",
                project="ProjectA",
                description="first sample",
                index_pair=IndexPair(
                    id="p1",
                    name="D701",
                    index1=Index(name="D701", sequence="ATTACTCG", index_type=IndexType.I7),
                    index2=Index(name="D501", sequence="TATAGCCT", index_type=IndexType.I5),
                ),
            ),
            Sample(
                sample_id="Sample_002",
                sample_name="Sample Two",
                project="ProjectA",
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
def novaseq6000_run():
    """Create a NovaSeq 6000 run for testing."""
    return SequencingRun(
        run_name="NovaSeq 6000 Test",
        instrument_platform=InstrumentPlatform.NOVASEQ_6000,
        flowcell_type="SP",
        run_cycles=RunCycles(151, 151, 10, 10),
        created_by="admin",
        created_at=datetime(2025, 7, 1, 8, 0, 0),
        samples=[
            Sample(
                sample_id="NS_001",
                sample_name="NS Sample 1",
                project="NSProject",
                lanes=[1, 2],
                index_pair=IndexPair(
                    id="p1",
                    name="D701",
                    index1=Index(name="D701", sequence="ATTACTCG", index_type=IndexType.I7),
                    index2=Index(name="D501", sequence="TATAGCCT", index_type=IndexType.I5),
                ),
            ),
        ],
    )


class TestSampleSheetV1ExporterHeader:
    """Tests for the [Header] section."""

    def test_header_iem_version(self, miseq_run):
        output = SampleSheetV1Exporter.export(miseq_run)
        assert "[Header]" in output
        assert "IEMFileVersion,4" in output

    def test_header_investigator_name(self, miseq_run):
        output = SampleSheetV1Exporter.export(miseq_run)
        assert "Investigator Name,testuser" in output

    def test_header_experiment_name(self, miseq_run):
        output = SampleSheetV1Exporter.export(miseq_run)
        assert "Experiment Name,MiSeq Test Run" in output

    def test_header_date(self, miseq_run):
        output = SampleSheetV1Exporter.export(miseq_run)
        assert "Date,2025-06-15" in output

    def test_header_workflow(self, miseq_run):
        output = SampleSheetV1Exporter.export(miseq_run)
        assert "Workflow,GenerateFASTQ" in output
        assert "Application,FASTQ Only" in output

    def test_header_description(self, miseq_run):
        output = SampleSheetV1Exporter.export(miseq_run)
        assert "Description,Test description" in output

    def test_header_chemistry(self, miseq_run):
        output = SampleSheetV1Exporter.export(miseq_run)
        assert "Chemistry,Default" in output

    def test_header_no_investigator_when_empty(self):
        run = SequencingRun(
            run_name="Test",
            instrument_platform=InstrumentPlatform.MISEQ,
            created_at=datetime(2025, 1, 1),
        )
        output = SampleSheetV1Exporter.export(run)
        assert "Investigator Name" not in output

    def test_header_csv_escaping(self):
        run = SequencingRun(
            run_name="Run, with comma",
            instrument_platform=InstrumentPlatform.MISEQ,
            created_at=datetime(2025, 1, 1),
        )
        output = SampleSheetV1Exporter.export(run)
        assert '"Run, with comma"' in output


class TestSampleSheetV1ExporterReads:
    """Tests for the [Reads] section."""

    def test_reads_section(self, miseq_run):
        output = SampleSheetV1Exporter.export(miseq_run)
        assert "[Reads]" in output
        lines = output.split("\n")
        reads_idx = lines.index("[Reads]")
        assert lines[reads_idx + 1] == "150"
        assert lines[reads_idx + 2] == "150"

    def test_reads_single_end(self):
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.MISEQ,
            run_cycles=RunCycles(150, 0, 10, 10),
            created_at=datetime(2025, 1, 1),
        )
        output = SampleSheetV1Exporter.export(run)
        lines = output.split("\n")
        reads_idx = lines.index("[Reads]")
        assert lines[reads_idx + 1] == "150"
        # No second read line
        assert lines[reads_idx + 2] == ""

    def test_reads_no_cycles(self):
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.MISEQ,
            created_at=datetime(2025, 1, 1),
        )
        output = SampleSheetV1Exporter.export(run)
        assert "[Reads]" in output


class TestSampleSheetV1ExporterSettings:
    """Tests for the [Settings] section."""

    def test_settings_section(self, miseq_run):
        output = SampleSheetV1Exporter.export(miseq_run)
        assert "[Settings]" in output
        assert "ReverseComplement,0" in output
        assert "BarcodeMismatchesIndex1,1" in output
        assert "BarcodeMismatchesIndex2,1" in output

    def test_settings_custom_mismatches(self):
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.MISEQ,
            barcode_mismatches_index1=2,
            barcode_mismatches_index2=0,
            created_at=datetime(2025, 1, 1),
        )
        output = SampleSheetV1Exporter.export(run)
        assert "BarcodeMismatchesIndex1,2" in output
        assert "BarcodeMismatchesIndex2,0" in output


class TestSampleSheetV1ExporterData:
    """Tests for the [Data] section."""

    def test_data_section_miseq_no_lanes(self, miseq_run):
        """MiSeq samples without lanes should not have Lane column."""
        output = SampleSheetV1Exporter.export(miseq_run)
        assert "[Data]" in output
        assert "Sample_ID,Sample_Name,Sample_Project,index,index2,Description" in output
        # No Lane column
        assert "Lane,Sample_ID" not in output

    def test_data_sample_rows_miseq(self, miseq_run):
        """MiSeq reads i5 in forward orientation - no reverse complement."""
        output = SampleSheetV1Exporter.export(miseq_run)
        # i5 should be as-is (forward orientation for MiSeq)
        assert "Sample_001,Sample One,ProjectA,ATTACTCG,TATAGCCT,first sample" in output
        assert "Sample_002,Sample Two,ProjectA,TCCGGAGA,ATAGAGGC," in output

    def test_data_novaseq6000_reverse_complement_i5(self, novaseq6000_run):
        """NovaSeq 6000 reads i5 in reverse-complement."""
        output = SampleSheetV1Exporter.export(novaseq6000_run)
        # TATAGCCT reverse-complemented is AGGCTATA
        assert "AGGCTATA" in output
        # Original i5 should NOT appear in data rows
        lines = output.split("\n")
        data_idx = lines.index("[Data]")
        data_lines = [l for l in lines[data_idx + 2:] if l.strip()]
        for line in data_lines:
            fields = line.split(",")
            # index2 is at position 5 (after Lane,Sample_ID,Sample_Name,Sample_Project,index)
            if len(fields) >= 6:
                assert fields[5] == "AGGCTATA"

    def test_data_with_lanes(self, novaseq6000_run):
        """NovaSeq 6000 with lane assignments should have Lane column and one row per lane."""
        output = SampleSheetV1Exporter.export(novaseq6000_run)
        assert "Lane,Sample_ID,Sample_Name,Sample_Project,index,index2,Description" in output
        # Should have two rows (one per lane)
        lines = output.split("\n")
        data_idx = lines.index("[Data]")
        data_lines = [l for l in lines[data_idx + 2:] if l.strip()]
        assert len(data_lines) == 2
        assert data_lines[0].startswith("1,")
        assert data_lines[1].startswith("2,")

    def test_data_empty_samples(self):
        """Export with no samples should still produce [Data] header."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.MISEQ,
            created_at=datetime(2025, 1, 1),
        )
        output = SampleSheetV1Exporter.export(run)
        assert "[Data]" in output
        assert "Sample_ID,Sample_Name,Sample_Project,index,index2,Description" in output

    def test_data_sample_without_index(self):
        """Sample without index should have empty index fields."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.MISEQ,
            created_at=datetime(2025, 1, 1),
            samples=[Sample(sample_id="NoIdx", sample_name="No Index")],
        )
        output = SampleSheetV1Exporter.export(run)
        assert "NoIdx,No Index,,,,\n" in output

    def test_data_csv_escaping(self):
        """Values with commas should be properly escaped."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.MISEQ,
            created_at=datetime(2025, 1, 1),
            samples=[
                Sample(
                    sample_id="S1",
                    sample_name="Name, with comma",
                    project="Proj",
                ),
            ],
        )
        output = SampleSheetV1Exporter.export(run)
        assert '"Name, with comma"' in output


class TestSampleSheetV1ExporterSectionOrder:
    """Test that sections appear in correct order."""

    def test_section_order(self, miseq_run):
        output = SampleSheetV1Exporter.export(miseq_run)
        header_pos = output.index("[Header]")
        reads_pos = output.index("[Reads]")
        settings_pos = output.index("[Settings]")
        data_pos = output.index("[Data]")
        assert header_pos < reads_pos < settings_pos < data_pos

    def test_no_dragen_sections(self, miseq_run):
        """V1 samplesheets should never have DRAGEN sections."""
        output = SampleSheetV1Exporter.export(miseq_run)
        assert "Dragen" not in output
        assert "BCLConvert" not in output

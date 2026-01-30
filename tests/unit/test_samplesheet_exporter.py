"""Tests for SampleSheet v2 exporter."""

import pytest

from sequencing_run_setup.models.analysis import Analysis, AnalysisType, DRAGENPipeline
from sequencing_run_setup.models.index import Index, IndexPair, IndexType
from sequencing_run_setup.models.sample import Sample
from sequencing_run_setup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from sequencing_run_setup.services.samplesheet_exporter import SampleSheetV2Exporter


class TestSampleSheetV2Exporter:
    """Tests for SampleSheetV2Exporter."""

    def test_export_header_section(self, sample_run):
        """Test [Header] section output."""
        output = SampleSheetV2Exporter.export(sample_run)

        assert "[Header]" in output
        assert "FileFormatVersion,2" in output
        assert "RunName,TestRun_001" in output
        assert "InstrumentPlatform,NovaSeq X Series" in output

    def test_export_reads_section(self, sample_run):
        """Test [Reads] section output."""
        output = SampleSheetV2Exporter.export(sample_run)

        assert "[Reads]" in output
        assert "Read1Cycles,151" in output
        assert "Read2Cycles,151" in output
        assert "Index1Cycles,10" in output
        assert "Index2Cycles,10" in output

    def test_export_bclconvert_settings(self, sample_run):
        """Test [BCLConvert_Settings] section output."""
        output = SampleSheetV2Exporter.export(sample_run)

        assert "[BCLConvert_Settings]" in output
        assert "BarcodeMismatchesIndex1,1" in output
        assert "BarcodeMismatchesIndex2,1" in output
        assert "FastqCompressionFormat,gzip" in output

    def test_export_bclconvert_data(self, sample_run):
        """Test [BCLConvert_Data] section output."""
        output = SampleSheetV2Exporter.export(sample_run)

        assert "[BCLConvert_Data]" in output
        assert "Sample_ID,index,index2,Sample_Project" in output
        assert "Sample_001,ATTACTCG,TATAGCCT,TestProject" in output

    def test_export_override_cycles_global(self, sample_run):
        """Test global OverrideCycles when all indexes same length."""
        output = SampleSheetV2Exporter.export(sample_run)

        # NovaSeq X reads i5 in reverse-complement, so Index2 segment is reversed
        assert "OverrideCycles,Y151;I8N2;N2I8;Y151" in output

    def test_export_override_cycles_global_forward_instrument(self):
        """Test global OverrideCycles for a forward-orientation instrument."""
        run = SequencingRun(
            run_name="MiSeq Run",
            instrument_platform=InstrumentPlatform.MISEQ_I100,
            flowcell_type="25M",
            run_cycles=RunCycles(150, 150, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1",
                        name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )

        output = SampleSheetV2Exporter.export(run)

        # MiSeq i100 reads i5 in forward orientation, so Index2 segment is NOT reversed
        assert "OverrideCycles,Y150;I8N2;I8N2;Y150" in output

    def test_export_override_cycles_per_sample(self, sample_run):
        """Test per-sample OverrideCycles when indexes differ."""
        # Add sample with different index length
        sample_run.add_sample(
            Sample(
                sample_id="Sample_002",
                index_pair=IndexPair(
                    id="diff",
                    name="diff",
                    index1=Index(
                        name="i7", sequence="ATCGATCGATCG", index_type=IndexType.I7
                    ),
                    index2=Index(
                        name="i5", sequence="GCTAGCTACCGG", index_type=IndexType.I5
                    ),
                ),
            )
        )

        output = SampleSheetV2Exporter.export(sample_run)

        # Should have per-sample override cycles column
        assert "Sample_ID,index,index2,Sample_Project,OverrideCycles" in output

    def test_export_with_lanes(self, sample_run):
        """Test export with lane assignments."""
        sample_run.samples[0].lanes = [1]

        output = SampleSheetV2Exporter.export(sample_run)

        # Should have Lane column
        assert "Lane,Sample_ID" in output
        assert "1,Sample_001" in output

    def test_export_with_dragen_germline(self, sample_run, sample_analysis):
        """Test export with DRAGEN Germline analysis."""
        sample_analysis.sample_ids = [sample_run.samples[0].sample_id]
        sample_run.add_analysis(sample_analysis)

        output = SampleSheetV2Exporter.export(sample_run)

        assert "[DragenGermline_Settings]" in output
        assert "ReferenceGenomeDir,hg38" in output
        assert "[DragenGermline_Data]" in output
        assert "Sample_001" in output

    def test_export_escapes_csv_values(self):
        """Test that values with commas are properly escaped."""
        run = SequencingRun(
            run_name="Run, with comma",
            run_cycles=RunCycles(151, 151, 10, 10),
        )

        output = SampleSheetV2Exporter.export(run)

        assert '"Run, with comma"' in output

    def test_export_empty_run(self):
        """Test exporting run with no samples."""
        run = SequencingRun(
            run_name="Empty",
            run_cycles=RunCycles(151, 151, 10, 10),
        )

        output = SampleSheetV2Exporter.export(run)

        # Should still have sections
        assert "[Header]" in output
        assert "[BCLConvert_Data]" in output

    def test_export_miseq_platform(self):
        """Test export for MiSeq i100 platform."""
        run = SequencingRun(
            run_name="MiSeq Run",
            instrument_platform=InstrumentPlatform.MISEQ_I100,
            flowcell_type="25M",
            run_cycles=RunCycles(150, 150, 10, 10),
        )

        output = SampleSheetV2Exporter.export(run)

        assert "InstrumentPlatform,MiSeq i100 Series" in output

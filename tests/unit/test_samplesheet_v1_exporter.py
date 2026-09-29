"""Tests for SampleSheet v1 (IEM) exporter."""

import pytest
from datetime import datetime

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from seqsetup.services.samplesheet_v1_exporter import (
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


class TestSampleSheetV1EscapeCsv:
    """Direct unit tests for the v1 exporter's _escape_csv helper."""

    def test_escape_csv_quotes_lone_cr(self):
        """A lone CR (Mac-style line ending) must be quoted, not written raw."""
        assert SampleSheetV1Exporter._escape_csv("foo\rbar") == '"foo\rbar"'

    def test_escape_csv_quotes_crlf(self):
        """A CRLF sequence must be quoted (preserving the \\r inside quotes)."""
        assert SampleSheetV1Exporter._escape_csv("foo\r\nbar") == '"foo\r\nbar"'


class TestSampleIdentifiersWrittenExactly:
    """v1 twin of the v2 test class: a valid sample name ('-S1') must reach
    [Data] exactly, not as "'-S1". bcl2fastq names FASTQs by Sample_Name,
    so that column is kept exact too."""

    def _export(self, sample_id="-S1", sample_name="-S1", project="", run_name="", full=False):
        run = SequencingRun(
            run_name=run_name,
            instrument_platform=InstrumentPlatform.MISEQ,
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[Sample(
                sample_id=sample_id,
                sample_name=sample_name,
                project=project,
                index_pair=IndexPair(
                    id="p1", name="p1",
                    index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                    index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                ),
            )],
        )
        output = SampleSheetV1Exporter.export(run)
        return output if full else output.split("[Data]", 1)[1]

    def test_leading_dash_kept_in_sample_id_and_name(self):
        assert "\n-S1,-S1," in self._export()

    def test_formula_like_text_still_guarded(self):
        assert "\n'=1+2,'=1+2," in self._export(sample_id="=1+2", sample_name="=1+2")

    def test_leading_dash_project_kept(self):
        # bcl2fastq uses Sample_Project as the output directory name.
        assert "\n-S1,-S1,-P1," in self._export(project="-P1")

    def test_leading_dash_run_name_kept_as_experiment_name(self):
        assert "\nExperiment Name,-Run1\n" in self._export(run_name="-Run1", full=True)


class TestSheetTextGuardV1:
    """The v1 writer refuses hidden characters it cannot make safe (audit
    2026-09 N-12)."""

    @pytest.mark.parametrize("char", ["\x00", "\x0b", "\x0c", "\x85", "\u2028"])
    def test_escape_csv_refuses_hidden_character(self, char):
        with pytest.raises(ValueError, match=f"U\\+{ord(char):04X}"):
            SampleSheetV1Exporter._escape_csv(f"N{char}X")

    def test_escape_csv_keeps_its_quoting_and_formula_guard(self):
        assert SampleSheetV1Exporter._escape_csv("a,b") == '"a,b"'
        assert SampleSheetV1Exporter._escape_csv("a\rb") == '"a\rb"'
        assert SampleSheetV1Exporter._escape_csv("\tx") == "'\tx"


class TestInvisibleCharacters:
    """The v1 writer refuses a zero-width space like any hidden character
    (spec 2026-09-29 Sample Sheet follow-ups, §3)."""

    def test_zero_width_space_in_sample_name_is_refused(self, sample_run):
        sample_run.samples[0].sample_name = "Sample​One"

        with pytest.raises(ValueError, match="U\\+200B"):
            SampleSheetV1Exporter.export(sample_run)

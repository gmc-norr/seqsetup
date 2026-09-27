"""Tests for SampleSheet v2 exporter."""

from pathlib import Path

import pytest
import yaml

from seqsetup.models.analysis import Analysis, AnalysisType, DRAGENPipeline
from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from seqsetup.models.test_profile import ApplicationProfileReference, TestProfile
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter


class TestSampleSheetV2Exporter:
    """Tests for SampleSheetV2Exporter."""

    def test_export_header_section(self, sample_run):
        """Test [Header] section output."""
        output = SampleSheetV2Exporter.export(sample_run)

        assert "[Header]" in output
        assert "FileFormatVersion,2" in output
        assert "RunName,TestRun_001" in output
        assert "InstrumentPlatform,NovaSeqXSeries" in output

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
        assert "FastqCompressionFormat,gzip" in output
        # Barcode mismatches are in BCLConvert_Data, not Settings (only when custom values)

    def test_export_bclconvert_data(self, sample_run):
        """Test [BCLConvert_Data] section output."""
        output = SampleSheetV2Exporter.export(sample_run)

        assert "[BCLConvert_Data]" in output
        # Column names use capitalized Index/Index2 for IMS compatibility
        # Sample_Project is in Cloud_Data section as ProjectName
        assert "Sample_ID,Index,Index2" in output
        assert "Sample_001,ATTACTCG,TATAGCCT" in output

    def test_export_override_cycles_global(self, sample_run):
        """Test global OverrideCycles when all indexes same length.

        Per Illumina BCL Convert: the OverrideCycles Index2 segment matches
        the orientation of the i5 sequence as it appears in the sample
        sheet (not the physical-read orientation). NovaSeq X sample sheets
        carry i5 in FORWARD orientation, so the Index2 token stays forward
        (``I8N2``), not reversed.
        """
        output = SampleSheetV2Exporter.export(sample_run)
        assert "OverrideCycles,Y151;I8N2;I8N2;Y151" in output

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

        # MiSeq i100 sample sheet carries i5 in forward orientation; Index2 forward too.
        assert "OverrideCycles,Y150;I8N2;I8N2;Y150" in output

    def test_export_override_cycles_global_rc_instrument(self):
        """For instruments whose sample sheet specifies i5 in reverse-complement
        orientation (e.g. NextSeq 500/550, NovaSeq 6000), the OverrideCycles
        Index2 token must also be reversed — N at the beginning per Illumina
        BCL Convert guidance.
        """
        run = SequencingRun(
            run_name="NextSeq Run",
            instrument_platform=InstrumentPlatform.NEXTSEQ_500_550,
            flowcell_type="High",
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # NextSeq 500/550 sample sheet carries i5 in RC → Index2 token reversed.
        assert "OverrideCycles,Y151;I8N2;N2I8;Y151" in output

    def test_adjust_override_cycles_comma_separator_on_rc_instrument(self):
        """A legacy comma-separated OverrideCycles must still get its Index2
        token RC-adjusted on an RC instrument. Previously split(';') saw one
        part, skipped the adjustment, and left Index2 desynced from the RC'd i5."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NEXTSEQ_500_550,
            flowcell_type="High",
            run_cycles=RunCycles(151, 151, 10, 10),
        )
        result = SampleSheetV2Exporter._adjust_override_cycles_for_instrument(
            "Y151,I8N2,I8N2,Y151", run
        )
        assert result == "Y151;I8N2;N2I8;Y151"

    def test_adjust_override_cycles_single_end_rc_instrument_flips_index2(self):
        """A single-end run has three segments (no Read2). The Index2 mask
        must still be flipped on an RC instrument, or it desyncs from the
        reverse-complemented i5."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NEXTSEQ_500_550,
            flowcell_type="High",
            run_cycles=RunCycles(151, 0, 10, 10),
        )
        result = SampleSheetV2Exporter._adjust_override_cycles_for_instrument(
            "Y151;I10;I8N2", run
        )
        assert result == "Y151;I10;N2I8"

    def test_adjust_override_cycles_legacy_four_segments_still_flips(self):
        """An older stored '...;Y0' value on a single-end run keeps the Index2
        flip it always had (validation now blocks it from Ready, but legacy
        live exports must not get worse)."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NEXTSEQ_500_550,
            flowcell_type="High",
            run_cycles=RunCycles(151, 0, 10, 10),
        )
        result = SampleSheetV2Exporter._adjust_override_cycles_for_instrument(
            "Y151;I10;I8N2;Y0", run
        )
        assert result == "Y151;I10;N2I8;Y0"

    def test_adjust_override_cycles_single_index_rc_instrument_unchanged(self):
        """No Index2 read (index2_cycles=0): nothing to flip."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NEXTSEQ_500_550,
            flowcell_type="High",
            run_cycles=RunCycles(151, 151, 10, 0),
        )
        result = SampleSheetV2Exporter._adjust_override_cycles_for_instrument(
            "Y151;I8N2;Y151", run
        )
        assert result == "Y151;I8N2;Y151"

    def test_comma_override_normalized_to_semicolon_on_forward_instrument(self):
        """BCL Convert v2 uses ';' as the OverrideCycles separator; a legacy
        comma-form override must be normalized to ';' on FORWARD instruments too,
        not emitted with literal commas the sequencer can't parse."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,  # forward orientation
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 10, 10),
        )
        result = SampleSheetV2Exporter._adjust_override_cycles_for_instrument(
            "Y151,I8N2,I8N2,Y151", run
        )
        assert result == "Y151;I8N2;I8N2;Y151"  # commas->';', no RC flip (forward)

    def test_single_index_sample_gets_computed_override_not_blank(self):
        """In a run that forces per-sample OverrideCycles, a single-index sample
        (index1 only, no index_pair, no explicit override) must get a COMPUTED
        OverrideCycles, not a blank cell — the fallback now keys on has_index."""
        run = SequencingRun(
            run_name="Mixed",
            instrument_platform=InstrumentPlatform.NOVASEQ_X,  # forward, no RC noise
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(sample_id="DUAL", index_pair=IndexPair(
                    id="p1", name="p1",
                    index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                    index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5))),
                Sample(sample_id="SINGLE", index1=Index(
                    name="j7", sequence="GGGGCCCC", index_type=IndexType.I7)),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # SINGLE: index1 8bp -> I8N2; absent index2 over 10 cycles -> N10.
        assert "Y151;I8N2;N10;Y151" in output

    def test_export_bclconvert_runtime_settings_emitted(self, sample_run):
        """no_lane_splitting / create_fastq_for_index_reads / adapter_behavior
        on the run model must appear in [BCLConvert_Settings]; silent drop
        would mean a clinician's toggle in the UI never reaches BCL Convert.
        """
        sample_run.no_lane_splitting = True
        sample_run.create_fastq_for_index_reads = True
        sample_run.adapter_behavior = "mask"
        output = SampleSheetV2Exporter.export(sample_run)
        assert "NoLaneSplitting,true" in output
        assert "CreateFastqForIndexReads,1" in output
        assert "AdapterBehavior,mask" in output

    def test_export_bclconvert_default_lane_split_emitted_as_false(self, sample_run):
        """Defaults still go on the wire so the value is deterministic — BCL
        Convert would otherwise apply its own default and the operator can't
        tell from the artifact what the run was configured for."""
        output = SampleSheetV2Exporter.export(sample_run)
        assert "NoLaneSplitting,false" in output
        assert "CreateFastqForIndexReads,0" in output
        # AdapterBehavior is omitted when "trim" (default) — see
        # _format_bclconvert_run_settings docstring.
        assert "AdapterBehavior" not in output

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
        assert "Sample_ID,Index,Index2,OverrideCycles" in output

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

    def test_escape_csv_quotes_lone_cr(self):
        """A lone CR (Mac-style line ending) must be quoted, not written raw."""
        assert SampleSheetV2Exporter._escape_csv("foo\rbar") == '"foo\rbar"'

    def test_escape_csv_quotes_crlf(self):
        """A CRLF sequence must be quoted (the \\n already triggers, but the \\r should be preserved inside quotes)."""
        assert SampleSheetV2Exporter._escape_csv("foo\r\nbar") == '"foo\r\nbar"'

    def test_export_normalizes_legacy_comma_override_to_semicolon(self):
        """A legacy comma-separated override_cycles is normalized to the BCL
        Convert ';' separator on export (regardless of instrument), so it is a
        single CSV cell with the correct separator — not emitted with literal
        commas (which BCL Convert can't parse and which would also split the
        row). Per-sample OverrideCycles column is emitted only when global
        inference fails (samples disagree on effective index lengths), so two
        samples with different index lengths force the per-sample path.
        """
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    override_cycles="Y151,I8,I8,Y151",  # legacy comma-separated form
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),  # 8 bp
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
                Sample(
                    sample_id="S2",
                    index_pair=IndexPair(
                        id="p2", name="p2",
                        index1=Index(name="i7b", sequence="TCCGGAGAGG", index_type=IndexType.I7),  # 10 bp
                        index2=Index(name="i5b", sequence="ATAGAGGCAA", index_type=IndexType.I5),
                    ),
                ),
            ],
        )

        output = SampleSheetV2Exporter.export(run)
        # Normalized to ';' (BCL Convert separator); no literal comma remains, so
        # no CSV-quoting is needed and the row keeps the right column count.
        assert "Y151;I8;I8;Y151" in output
        assert '"Y151,I8,I8,Y151"' not in output

    def test_export_escapes_index_sequence_with_comma(self):
        """The non-profile BCLConvert_Data path must CSV-escape index sequences,
        in parity with the profile-driven path. Index has no __setattr__, so a
        post-construction reassignment bypasses DNA validation; a stray comma
        must still be quoted, not split the row into the wrong column count."""
        idx1 = Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7)
        idx1.sequence = "ATTAC,TCG"  # bypasses Index.__post_init__ DNA validation
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=idx1,
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        assert '"ATTAC,TCG"' in output

    def test_export_escapes_reference_genome_with_comma(self):
        """analysis.reference_genome with a comma must be quoted in DRAGEN sections."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
            analyses=[
                Analysis(
                    name="malicious",
                    analysis_type=AnalysisType.DRAGEN_ONBOARD,
                    dragen_pipeline=DRAGENPipeline.GERMLINE,
                    reference_genome="hg38,injected",
                    sample_ids=["S1"],
                ),
            ],
        )

        output = SampleSheetV2Exporter.export(run)
        assert '"hg38,injected"' in output

    def test_export_escapes_application_profile_data_value_with_comma(self):
        """profile.data fallback values must be CSV-quoted in the Data section.

        Admin-provided default values in an ApplicationProfile's ``data`` dict
        flow into BCLConvert_Data rows for fields the sample doesn't override.
        A comma in any such value would shift columns downstream."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[
                Sample(
                    sample_id="S1",
                    test_id="WGS",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        app_profile = ApplicationProfile(
            name="BCLConvertNextera",
            version="1.0.0",
            application_type="BclConvert",
            application_name="BCLConvert",
            settings={},
            data_fields=["Sample_ID", "Index", "Index2", "ExtraField"],
            data={"ExtraField": "value,with,commas"},
        )
        tp = TestProfile(
            test_type="WGS", test_name="WGS", version="1.0.0",
            application_profiles=[ApplicationProfileReference(profile_name="BCLConvertNextera", profile_version="1.0.0")],
        )
        test_profile_repo = _StubTestProfileRepo({"WGS": tp})
        app_profile_repo = _StubAppProfileRepo({("BCLConvertNextera", "1.0.0"): app_profile})

        output = SampleSheetV2Exporter.export(run, test_profile_repo, app_profile_repo)
        assert '"value,with,commas"' in output

    def test_export_escapes_application_profile_setting_with_comma(self):
        """profile.settings keys/values with commas must be CSV-quoted in the Settings section."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[
                Sample(
                    sample_id="S1",
                    test_id="WGS",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        app_profile = ApplicationProfile(
            name="BCLConvertNextera",
            version="1.0.0",
            application_type="BclConvert",
            application_name="BCLConvert",
            settings={"SoftwareVersion": "4.3,injected"},
            data_fields=["Sample_ID", "Index", "Index2"],
            data={},
        )
        tp = TestProfile(
            test_type="WGS",
            test_name="WGS",
            version="1.0.0",
            application_profiles=[
                ApplicationProfileReference(profile_name="BCLConvertNextera", profile_version="1.0.0"),
            ],
        )
        test_profile_repo = _StubTestProfileRepo({"WGS": tp})
        app_profile_repo = _StubAppProfileRepo({("BCLConvertNextera", "1.0.0"): app_profile})

        output = SampleSheetV2Exporter.export(run, test_profile_repo, app_profile_repo)
        # The value contained a comma — must be quoted so it stays a single CSV field.
        assert '"4.3,injected"' in output

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

        # samplesheet_name for MiSeq i100 is "MiSeqi100Series"
        assert "InstrumentPlatform,MiSeqi100Series" in output

    def test_export_novaseq_x_i5_forward(self):
        """NovaSeq X: BCL Convert expects i5 in forward orientation."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # i5 should be forward (as stored) for NovaSeq X
        assert "S1,ATTACTCG,TATAGCCT," in output

    def test_export_novaseq_6000_i5_reverse_complement(self):
        """NovaSeq 6000: BCL Convert expects i5 reverse-complemented."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_6000,
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # TATAGCCT reverse-complemented is AGGCTATA
        assert "S1,ATTACTCG,AGGCTATA" in output
        # Check BCLConvert_Data section only (not Cloud_Data where forward i5 appears in LibraryName)
        bclconvert_data = output.split("[BCLConvert_Data]")[1].split("[Cloud_")[0]
        assert "TATAGCCT" not in bclconvert_data

    def test_export_nextseq_500_i5_reverse_complement(self):
        """NextSeq 500/550: BCL Convert expects i5 reverse-complemented."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NEXTSEQ_500_550,
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # TATAGCCT reverse-complemented is AGGCTATA
        assert "S1,ATTACTCG,AGGCTATA," in output

    def test_export_miseq_classic_i5_forward(self):
        """MiSeq (classic): BCL Convert expects i5 in forward orientation."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.MISEQ,
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # i5 should be forward for MiSeq
        assert "S1,ATTACTCG,TATAGCCT," in output

    def test_export_miniseq_i5_reverse_complement(self):
        """MiniSeq: BCL Convert expects i5 reverse-complemented."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.MINISEQ,
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # TATAGCCT reverse-complemented is AGGCTATA
        assert "S1,ATTACTCG,AGGCTATA," in output


class _StubTestProfileRepo:
    """In-memory test profile repo keyed by test_type."""

    def __init__(self, profiles_by_test_type: dict):
        self._profiles = profiles_by_test_type

    def get_by_test_type(self, test_type):
        return self._profiles.get(test_type)


class _StubAppProfileRepo:
    """In-memory application profile repo keyed by (name, version)."""

    def __init__(self, profiles_by_key: dict):
        self._profiles = profiles_by_key

    def get_by_name_version(self, name, version):
        return self._profiles.get((name, version))


class TestApplicationSectionsAcrossTestProfiles:
    """When two TestProfiles reference the same ApplicationProfile, samples from
    every referencing test_id must appear in that profile's data section.

    Without this guarantee, the exporter writes the section once with only the
    first test_id's samples and silently drops the rest — they never reach the
    sequencer's demultiplexer.
    """

    def _make_app_profile(self):
        return ApplicationProfile(
            name="BCLConvertNextera",
            version="1.0.0",
            application_type="BclConvert",
            application_name="BCLConvert",
            settings={"SoftwareVersion": "4.3.6"},
            data_fields=["Sample_ID", "Index", "Index2"],
            data={},
        )

    def _make_test_profile(self, test_type):
        return TestProfile(
            test_type=test_type,
            test_name=test_type,
            version="1.0.0",
            application_profiles=[
                ApplicationProfileReference(
                    profile_name="BCLConvertNextera",
                    profile_version="1.0.0",
                ),
            ],
        )

    def _make_sample(self, sample_id, test_id, i7, i5):
        return Sample(
            sample_id=sample_id,
            test_id=test_id,
            index_pair=IndexPair(
                id=f"pair_{sample_id}",
                name=f"pair_{sample_id}",
                index1=Index(name=f"i7_{sample_id}", sequence=i7, index_type=IndexType.I7),
                index2=Index(name=f"i5_{sample_id}", sequence=i5, index_type=IndexType.I5),
            ),
        )

    @staticmethod
    def _extract_section(output: str, section_name: str) -> str:
        """Return the body of [section_name] (everything until the next [Section] or EOF)."""
        marker = f"[{section_name}]"
        start = output.index(marker) + len(marker)
        tail = output[start:]
        # Section ends at the next "[...]" header
        next_idx = tail.find("\n[")
        return tail if next_idx == -1 else tail[:next_idx]

    def test_shared_app_profile_includes_samples_from_every_test_id(self):
        """A sample whose test_id resolves to an already-emitted ApplicationProfile must still appear in that profile's data section."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[
                self._make_sample("S_WGS", "WGS", "ATTACTCG", "TATAGCCT"),
                self._make_sample("S_RNA", "RNA", "TCCGGAGA", "ATAGAGGC"),
            ],
        )
        app_profile = self._make_app_profile()
        test_profile_repo = _StubTestProfileRepo({
            "WGS": self._make_test_profile("WGS"),
            "RNA": self._make_test_profile("RNA"),
        })
        app_profile_repo = _StubAppProfileRepo({
            ("BCLConvertNextera", "1.0.0"): app_profile,
        })

        output = SampleSheetV2Exporter.export(run, test_profile_repo, app_profile_repo)
        # Pin the assertions to BCLConvert_Data — both samples also legitimately
        # appear in Cloud_Data, so a global `in output` check would not catch the bug.
        bcl_data = self._extract_section(output, "BCLConvert_Data")
        assert "S_WGS" in bcl_data
        assert "S_RNA" in bcl_data

    def test_shared_app_profile_section_written_only_once(self):
        """The shared section must not be duplicated (header line appears once)."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[
                self._make_sample("S_WGS", "WGS", "ATTACTCG", "TATAGCCT"),
                self._make_sample("S_RNA", "RNA", "TCCGGAGA", "ATAGAGGC"),
            ],
        )
        app_profile = self._make_app_profile()
        test_profile_repo = _StubTestProfileRepo({
            "WGS": self._make_test_profile("WGS"),
            "RNA": self._make_test_profile("RNA"),
        })
        app_profile_repo = _StubAppProfileRepo({
            ("BCLConvertNextera", "1.0.0"): app_profile,
        })

        output = SampleSheetV2Exporter.export(run, test_profile_repo, app_profile_repo)

        assert output.count("[BCLConvert_Data]") == 1
        assert output.count("[BCLConvert_Settings]") == 1

    def test_single_index_sample_override_cycles_on_profile_export_path(self):
        """The production (profile-driven) export path must compute OverrideCycles
        for a single-index sample (index1 only, no index_pair, no explicit
        override) — not emit a blank cell, which would misroute its reads."""
        app_profile = ApplicationProfile(
            name="BCLConvertNextera",
            version="1.0.0",
            application_type="BclConvert",
            application_name="BCLConvert",
            settings={"SoftwareVersion": "4.3.6"},
            data_fields=["Sample_ID", "OverrideCycles"],
            data={},
        )
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[Sample(sample_id="S_SINGLE", test_id="WGS", index1=Index(
                name="i7", sequence="ATTACTCG", index_type=IndexType.I7))],
        )
        test_profile_repo = _StubTestProfileRepo({"WGS": self._make_test_profile("WGS")})
        app_profile_repo = _StubAppProfileRepo({("BCLConvertNextera", "1.0.0"): app_profile})

        output = SampleSheetV2Exporter.export(run, test_profile_repo, app_profile_repo)
        # index1 8bp over 8 index1 cycles -> I8; absent index2 over 8 -> N8.
        # The single-index sample's OverrideCycles cell must be computed, not blank.
        assert "S_SINGLE,Y151;I8;N8;Y151" in output


SHIPPED_BCLCONVERT_PROFILE = (
    Path(__file__).resolve().parents[2]
    / "config" / "profiles" / "application_profiles" / "dragen" / "BCLConvertNextera.yaml"
)


class TestProfileDrivenBclConvertData:
    """The profile-driven [BCLConvert_Data] section must match what BCL Convert
    expects: one row per (sample, lane), and the column names the profile's
    Translate mapping declares (e.g. IndexI7 -> Index).

    A multi-lane sample written with only its first lane sends its reads from
    the other lanes to Undetermined. An 'IndexI7' header is not a column BCL
    Convert recognises, so the sheet is rejected or demultiplexed without indexes.
    """

    def _make_sample(self, sample_id, lanes):
        return Sample(
            sample_id=sample_id,
            test_id="WGS",
            lanes=lanes,
            index_pair=IndexPair(
                id=f"pair_{sample_id}",
                name=f"pair_{sample_id}",
                index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
            ),
        )

    def _make_app_profile(self, data_fields, translate=None):
        return ApplicationProfile(
            name="BCLConvertNextera",
            version="1.0.0",
            application_type="Dragen",
            application_name="BCLConvert",
            settings={"SoftwareVersion": "4.3.6"},
            data_fields=data_fields,
            data={},
            translate=translate or {},
        )

    def _export(self, app_profile, samples, section="BCLConvert_Data"):
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=samples,
        )
        test_profile_repo = _StubTestProfileRepo({
            "WGS": TestProfile(
                test_type="WGS",
                test_name="WGS",
                version="1.0.0",
                application_profiles=[
                    ApplicationProfileReference(
                        profile_name=app_profile.name,
                        profile_version=app_profile.version,
                    ),
                ],
            ),
        })
        app_profile_repo = _StubAppProfileRepo({
            (app_profile.name, app_profile.version): app_profile,
        })
        output = SampleSheetV2Exporter.export(run, test_profile_repo, app_profile_repo)
        return TestApplicationSectionsAcrossTestProfiles._extract_section(
            output, section
        ).strip().splitlines()

    def test_multi_lane_sample_gets_one_row_per_lane(self):
        profile = self._make_app_profile(["Sample_ID", "Lane", "Index", "Index2"])
        lines = self._export(profile, [self._make_sample("S1", [1, 2])])
        assert lines[1:] == [
            "S1,1,ATTACTCG,TATAGCCT",
            "S1,2,ATTACTCG,TATAGCCT",
        ]

    def test_sample_without_lanes_gets_single_row_with_blank_lane(self):
        profile = self._make_app_profile(["Sample_ID", "Lane", "Index", "Index2"])
        lines = self._export(profile, [self._make_sample("S1", [])])
        assert lines[1:] == ["S1,,ATTACTCG,TATAGCCT"]

    def test_lanes_do_not_duplicate_rows_when_profile_has_no_lane_column(self):
        profile = self._make_app_profile(["Sample_ID", "Index", "Index2"])
        lines = self._export(profile, [self._make_sample("S1", [1, 2])])
        assert lines[1:] == ["S1,ATTACTCG,TATAGCCT"]

    def test_header_uses_translated_column_names(self):
        profile = self._make_app_profile(
            ["Sample_ID", "Lane", "IndexI7", "IndexI5"],
            translate={"IndexI7": "Index", "IndexI5": "Index2"},
        )
        lines = self._export(profile, [self._make_sample("S1", [1])])
        assert lines == [
            "Sample_ID,Lane,Index,Index2",
            "S1,1,ATTACTCG,TATAGCCT",
        ]

    def test_translated_field_gets_value_of_its_target_column(self):
        # A field renamed to a real BCL Convert column must be filled like
        # that column — a Sample_ID header over blank cells, or a Lane header
        # without per-lane rows, would be worse than no translation at all.
        profile = self._make_app_profile(
            ["SampleID", "LaneNo", "Index", "Index2"],
            translate={"SampleID": "Sample_ID", "LaneNo": "Lane"},
        )
        lines = self._export(profile, [self._make_sample("S1", [1, 2])])
        assert lines == [
            "Sample_ID,Lane,Index,Index2",
            "S1,1,ATTACTCG,TATAGCCT",
            "S1,2,ATTACTCG,TATAGCCT",
        ]

    def test_profile_with_empty_translate_key_exports(self):
        # A YAML "Translate:" key with no entries loads as None.
        data = yaml.safe_load(SHIPPED_BCLCONVERT_PROFILE.read_text())
        data["DataFields"] = ["Sample_ID", "Lane", "Index", "Index2"]
        data["Translate"] = None
        profile = ApplicationProfile.from_yaml(data, "test.yaml")
        lines = self._export(profile, [self._make_sample("S1", [1])])
        assert lines == ["Sample_ID,Lane,Index,Index2", "S1,1,ATTACTCG,TATAGCCT"]

    def test_non_bclconvert_section_keeps_one_row_per_sample(self):
        # Per-lane rows are a demultiplexing concept; other application
        # sections keep their previous single row (first lane).
        profile = ApplicationProfile(
            name="GermlineWGS",
            version="1.0.0",
            application_type="Dragen",
            application_name="DragenGermline",
            data_fields=["Sample_ID", "Lane"],
            data={},
        )
        lines = self._export(
            profile, [self._make_sample("S1", [1, 2])], section="DragenGermline_Data"
        )
        assert lines == ["Sample_ID,Lane", "S1,1"]

    def test_shipped_bclconvert_nextera_profile_exports_valid_data_section(self):
        profile = ApplicationProfile.from_yaml(
            yaml.safe_load(SHIPPED_BCLCONVERT_PROFILE.read_text()),
            str(SHIPPED_BCLCONVERT_PROFILE),
        )
        lines = self._export(profile, [self._make_sample("S1", [1, 2])])
        header = lines[0].split(",")
        assert header[:4] == ["Sample_ID", "Lane", "Index", "Index2"]
        assert "IndexI7" not in header
        assert "IndexI5" not in header
        rows = [line.split(",") for line in lines[1:]]
        assert [r[:4] for r in rows] == [
            ["S1", "1", "ATTACTCG", "TATAGCCT"],
            ["S1", "2", "ATTACTCG", "TATAGCCT"],
        ]


class TestSampleIdentifiersWrittenExactly:
    """A sample name made only of letters, digits, '-' and '_' is valid and
    must reach the sheet exactly as entered. The spreadsheet-formula guard
    used to prefix "'" to a leading '-', so '-S1' became "'-S1": the FASTQ
    and LIMS names no longer matched the approved sample. Such a name cannot
    carry a formula payload, so it needs no guard; other text keeps it."""

    def _run(self, sample_id="-S1", analysis=None):
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[Sample(
                sample_id=sample_id,
                test_id="WGS",
                index_pair=IndexPair(
                    id="p1", name="p1",
                    index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                    index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                ),
            )],
        )
        if analysis:
            run.add_analysis(analysis)
        return run

    def _section(self, output, name):
        return TestApplicationSectionsAcrossTestProfiles._extract_section(output, name)

    def test_leading_dash_kept_in_bclconvert_data(self):
        output = SampleSheetV2Exporter.export(self._run())
        assert "\n-S1,ATTACTCG,TATAGCCT" in self._section(output, "BCLConvert_Data")

    def test_leading_dash_kept_in_cloud_data(self):
        output = SampleSheetV2Exporter.export(self._run())
        cloud = self._section(output, "Cloud_Data")
        assert "\n-S1," in cloud
        assert ",-S1_ATTACTCG_TATAGCCT" in cloud

    def test_leading_dash_kept_in_profile_data_section(self):
        profile = ApplicationProfile(
            name="BCLConvertNextera", version="1.0.0",
            application_type="Dragen", application_name="BCLConvert",
            data_fields=["Sample_ID", "Index"], data={},
        )
        test_profile_repo = _StubTestProfileRepo({"WGS": TestProfile(
            test_type="WGS", test_name="WGS", version="1.0.0",
            application_profiles=[ApplicationProfileReference(
                profile_name="BCLConvertNextera", profile_version="1.0.0")],
        )})
        app_profile_repo = _StubAppProfileRepo({("BCLConvertNextera", "1.0.0"): profile})
        output = SampleSheetV2Exporter.export(self._run(), test_profile_repo, app_profile_repo)
        assert "\n-S1,ATTACTCG" in self._section(output, "BCLConvert_Data")

    def test_leading_dash_kept_in_dragen_data(self):
        analysis = Analysis(
            name="Germline", analysis_type=AnalysisType.DRAGEN_ONBOARD,
            dragen_pipeline=DRAGENPipeline.GERMLINE, reference_genome="hg38",
            sample_ids=["-S1"],
        )
        output = SampleSheetV2Exporter.export(self._run(analysis=analysis))
        assert "\n-S1" in self._section(output, "DragenGermline_Data")

    def test_formula_like_text_still_guarded(self):
        # Not a valid sample name: validation blocks it, and the sheet keeps
        # the formula guard in case it is ever opened in a spreadsheet.
        output = SampleSheetV2Exporter.export(self._run(sample_id="=1+2"))
        assert "\n'=1+2," in self._section(output, "BCLConvert_Data")

    def test_leading_dash_run_name_kept_in_header_and_cloud_project(self):
        run = self._run()
        run.run_name = "-Run1"
        output = SampleSheetV2Exporter.export(run)
        assert "\nRunName,-Run1\n" in output
        assert "\n-S1,-Run1," in self._section(output, "Cloud_Data")


class TestSheetTextGuards:
    """The v2 writer refuses text it cannot make safe (audit 2026-09 N-10,
    N-11, N-12). Mark Ready then fails and the run stays Draft."""

    @pytest.mark.parametrize("char", [
        "\x00", "\x0b", "\x0c", "\x1f", "\x7f", "\x85", " ", " ",
    ])
    def test_escape_csv_refuses_hidden_character(self, char):
        with pytest.raises(ValueError, match=f"U\\+{ord(char):04X}"):
            SampleSheetV2Exporter._escape_csv(f"N{char}X")

    def test_escape_csv_error_does_not_contain_the_text(self):
        with pytest.raises(ValueError) as exc:
            SampleSheetV2Exporter._escape_csv("Patient-Name\x00X")
        assert "Patient-Name" not in str(exc.value)

    def test_escape_csv_keeps_its_quoting_and_formula_guard(self):
        assert SampleSheetV2Exporter._escape_csv("a,b") == '"a,b"'
        assert SampleSheetV2Exporter._escape_csv('a"b') == '"a""b"'
        assert SampleSheetV2Exporter._escape_csv("a\nb") == '"a\nb"'
        assert SampleSheetV2Exporter._escape_csv("\tx") == "'\tx"
        assert SampleSheetV2Exporter._escape_csv("Åsa Öberg") == "Åsa Öberg"

    def test_identifier_with_hidden_character_is_refused(self):
        with pytest.raises(ValueError):
            SampleSheetV2Exporter._escape_identifier("S\x001")

    def test_bad_samplesheet_name_is_refused(self, sample_run, monkeypatch):
        monkeypatch.setattr(
            "seqsetup.services.samplesheet_v2_exporter.get_samplesheet_platform_name",
            lambda platform: "NovaSeqXSeries\n[Cloud_Data]",
        )
        with pytest.raises(ValueError, match="sample sheet name"):
            SampleSheetV2Exporter.export(sample_run)

    def test_bad_software_version_is_refused(self, sample_run, monkeypatch):
        monkeypatch.setattr(
            "seqsetup.services.samplesheet_v2_exporter.get_bclconvert_software_version",
            lambda platform: "4.3.6\n[Junk]",
        )
        with pytest.raises(ValueError, match="software version"):
            SampleSheetV2Exporter.export(sample_run)

    def test_bad_application_name_is_refused(self):
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[Sample(
                sample_id="S1",
                test_id="WGS",
                index_pair=IndexPair(
                    id="p1", name="p1",
                    index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                    index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                ),
            )],
        )
        app_profile = ApplicationProfile(
            name="Bad", version="1.0.0", application_type="Custom",
            application_name="BCLConvert]\n[Junk",
            settings={}, data_fields=["Sample_ID"], data={},
        )
        tp = TestProfile(
            test_type="WGS", test_name="WGS", version="1.0.0",
            application_profiles=[ApplicationProfileReference(profile_name="Bad", profile_version="1.0.0")],
        )

        with pytest.raises(ValueError, match="ApplicationName"):
            SampleSheetV2Exporter.export(
                run,
                _StubTestProfileRepo({"WGS": tp}),
                _StubAppProfileRepo({("Bad", "1.0.0"): app_profile}),
            )

    def test_plain_names_are_written_unchanged(self, sample_run):
        output = SampleSheetV2Exporter.export(sample_run)

        assert "InstrumentPlatform,NovaSeqXSeries" in output
        assert "SoftwareVersion,4.3.6" in output
